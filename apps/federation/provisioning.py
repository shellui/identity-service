"""Regional provisioning API called by the dashboard (saas-service).

Every call carries a short-lived RS256 assertion signed with the dashboard's provisioning key,
pinned on this deployment. The assertion is bound to the HTTP method, the path with query, and a
SHA-256 of the raw body. Writes need an ``Idempotency-Key``. Served only when the role is region
and a provisioning key is configured; otherwise every route answers 404.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.text import slugify
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from apps.authapi.magic_link import is_staff_account
from apps.authapi.oauth_user import normalize_oauth_email
from apps.companies.access import set_company_access
from apps.companies.models import Company, CompanyOAuthRedirect
from apps.federation.http import FederationView
from apps.federation.models import (
    AssertionUse,
    CompanyPlan,
    ProvisionedCompany,
    ProvisioningReceipt,
    UpstreamAccount,
)
from apps.federation.role import is_region
from apps.federation.signing import CLOCK_SKEW
from apps.federation.users import create_unprivileged_user

logger = logging.getLogger(__name__)
User = get_user_model()

SCOPE = 'provisioning'
MAX_LIFETIME = 300
PAGE_SIZE = 200
_KEY_RE = re.compile(r'^[A-Za-z0-9._:-]{1,200}$')
_ACCESS_MODES = {Company.ACCESS_PUBLIC, Company.ACCESS_DOMAIN, Company.ACCESS_INVITE}


class ProvisioningError(Exception):
    def __init__(self, status: int, code: str, detail: str, extra: dict | None = None):
        self.status = status
        self.code = code
        self.detail = detail
        self.extra = extra or {}
        super().__init__(code)

    def response(self) -> Response:
        return Response({'detail': self.detail, 'error_code': self.code, **self.extra}, status=self.status)


def provisioning_enabled() -> bool:
    return bool(
        is_region()
        and getattr(settings, 'PROVISIONING_PUBLIC_KEY', '')
        and getattr(settings, 'PROVISIONING_ISSUER', '')
        and provisioning_audience()
        and (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip()
    )


def provisioning_audience() -> str:
    configured = (getattr(settings, 'PROVISIONING_AUDIENCE', '') or '').strip()
    if configured:
        return configured
    from apps.federation.parsing import hostname_of

    return hostname_of(getattr(settings, 'JWT_ISSUER', None) or '')


def b64_sha256(raw: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode('ascii')


def verify_assertion(request) -> dict:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        raise ProvisioningError(401, 'invalid_assertion', 'A signed assertion is required.')
    token = header.split(' ', 1)[1].strip()
    try:
        unverified = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion was rejected.') from exc
    if unverified.get('alg') != 'RS256':
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion was rejected.')
    expected_kid = (getattr(settings, 'PROVISIONING_KEY_ID', '') or '').strip()
    if expected_kid and unverified.get('kid') != expected_kid:
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion was rejected.')
    try:
        claims = jwt.decode(
            token,
            settings.PROVISIONING_PUBLIC_KEY,
            algorithms=['RS256'],
            audience=provisioning_audience(),
            issuer=settings.PROVISIONING_ISSUER,
            leeway=CLOCK_SKEW,
            options={'require': ['exp', 'iat', 'iss', 'aud', 'jti', 'sub']},
        )
    except jwt.InvalidTokenError as exc:
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion was rejected.') from exc
    if claims.get('scope') != SCOPE:
        raise ProvisioningError(403, 'invalid_scope', 'Assertion scope must be provisioning.')
    try:
        lifetime = int(claims['exp']) - int(claims['iat'])
    except (TypeError, ValueError) as exc:
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion was rejected.') from exc
    if lifetime > MAX_LIFETIME:
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion lifetime is too long.')
    if claims.get('htm') != request.method or claims.get('htu') != request.get_full_path():
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion is not for this request.')
    if claims.get('bh') != b64_sha256(request.body or b''):
        raise ProvisioningError(401, 'invalid_assertion', 'Assertion does not match the body.')
    jti = str(claims['jti'])[:128]
    try:
        with transaction.atomic():
            AssertionUse.objects.create(jti=jti, idempotency_key=_header_key(request) or '')
    except IntegrityError as exc:
        logger.info('rejected replayed provisioning assertion')
        raise ProvisioningError(401, 'assertion_replayed', 'Assertion was already used.') from exc
    return claims


def _header_key(request) -> str:
    return (request.headers.get('Idempotency-Key') or '').strip()


class _ProvisioningView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def _run(self, request, work, *, write: bool):
        if not provisioning_enabled():
            return Response(status=404)
        try:
            verify_assertion(request)
            if not write:
                return work()
            return _idempotent(request, work)
        except ProvisioningError as exc:
            return exc.response()

    def _body(self, request) -> dict:
        raw = request.body or b''
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ProvisioningError(400, 'invalid_request', 'Body must be JSON.') from exc
        if not isinstance(data, dict):
            raise ProvisioningError(400, 'invalid_request', 'Body must be a JSON object.')
        return data


def _idempotent(request, work) -> Response:
    key = _header_key(request)
    if not _KEY_RE.fullmatch(key):
        raise ProvisioningError(400, 'idempotency_key_required', 'Idempotency-Key is required.')
    request_hash = hashlib.sha256(
        request.method.encode() + b' ' + request.get_full_path().encode() + b'\n' + (request.body or b'')
    ).hexdigest()
    existing = ProvisioningReceipt.objects.filter(idempotency_key=key).first()
    if existing is not None:
        if existing.body_hash != request_hash:
            raise ProvisioningError(
                409, 'idempotency_conflict', 'Idempotency-Key was already used for a different request.'
            )
        return Response(existing.response_body, status=existing.status_code)
    try:
        with transaction.atomic():
            response = work()
            if 200 <= response.status_code < 300:
                ProvisioningReceipt.objects.create(
                    idempotency_key=key,
                    body_hash=request_hash,
                    status_code=response.status_code,
                    response_body=response.data,
                )
    except IntegrityError:
        existing = ProvisioningReceipt.objects.filter(idempotency_key=key).first()
        if existing is not None and existing.body_hash == request_hash:
            return Response(existing.response_body, status=existing.status_code)
        raise ProvisioningError(409, 'conflict', 'The request conflicts with existing data.')
    return response


class ProvisioningCompaniesView(_ProvisioningView):
    def get(self, request):
        def work():
            if request.GET.get('linked') != 'shellui':
                raise ProvisioningError(400, 'invalid_request', 'linked=shellui is required.')
            try:
                after = int(request.GET.get('after') or 0)
            except ValueError as exc:
                raise ProvisioningError(400, 'invalid_request', 'after must be an integer.') from exc
            rows = list(
                ProvisionedCompany.objects.select_related('company')
                .filter(company_id__gt=after)
                .order_by('company_id')[: PAGE_SIZE + 1]
            )
            more = len(rows) > PAGE_SIZE
            rows = rows[:PAGE_SIZE]
            next_url = None
            if more:
                next_url = request.build_absolute_uri(
                    f'{request.path}?linked=shellui&after={rows[-1].company_id}'
                )
            return Response({'results': [_summary(row) for row in rows], 'next': next_url})

        return self._run(request, work, write=False)

    def post(self, request):
        return self._run(request, lambda: _create(self._body(request)), write=True)


class ProvisioningCompanyView(_ProvisioningView):
    def get(self, request, company_id: int):
        return self._run(request, lambda: Response(_detail(_provisioned(company_id))), write=False)

    def patch(self, request, company_id: int):
        return self._run(request, lambda: _update(_provisioned(company_id), self._body(request)), write=True)

    def delete(self, request, company_id: int):
        return self._run(request, lambda: _schedule_deletion(_provisioned(company_id)), write=True)


class ProvisioningLimitsView(_ProvisioningView):
    def put(self, request, company_id: int):
        return self._run(request, lambda: _put_limits(_provisioned(company_id), self._body(request)), write=True)


class CompanyPlanView(FederationView):
    """Limits and status for regional services. Members of the company only."""

    permission_classes = [IsAuthenticated]

    def get(self, request, company_id: int):
        if not is_region():
            return Response(status=404)
        company = Company.objects.filter(pk=company_id, members=request.user).first()
        if company is None:
            return Response({'error': 'Not found.'}, status=404)
        plan = CompanyPlan.objects.filter(company=company).first()
        row = ProvisionedCompany.objects.filter(company=company).first()
        return Response(
            {
                'company_id': company.pk,
                'limits': plan.limits if plan else {},
                'limits_version': row.limits_version if row else 0,
                'status': row.status if row else ProvisionedCompany.STATUS_ACTIVE,
            }
        )


def _provisioned(company_id: int) -> ProvisionedCompany:
    row = ProvisionedCompany.objects.select_related('company').filter(company_id=company_id).first()
    if row is None:
        raise ProvisioningError(404, 'not_found', 'Company not found.')
    return row


def _summary(row: ProvisionedCompany) -> dict:
    return {
        'id': str(row.company_id),
        'global_company_id': row.global_company_id,
        'name': row.company.name,
        'status': row.status,
        'plan': row.plan,
        'limits_version': row.limits_version,
    }


def _detail(row: ProvisionedCompany) -> dict:
    owners = set(row.company.owners.values_list('pk', flat=True))
    subjects = list(
        UpstreamAccount.objects.filter(user_id__in=owners, issuer=_global_issuer())
        .order_by('pk')
        .values_list('sub', flat=True)
    )
    return {**_summary(row), 'owners': [{'subject': sub} for sub in subjects]}


def _global_issuer() -> str:
    return (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip().rstrip('/')


def _string(data: dict, key: str, *, max_length: int, required: bool = True) -> str:
    value = data.get(key)
    if value is None and not required:
        return ''
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ProvisioningError(400, 'invalid_request', f'{key} is required (max {max_length} characters).')
    return value.strip()


def _create(data: dict) -> Response:
    global_id = _string(data, 'global_company_id', max_length=64)
    name = _string(data, 'name', max_length=255)
    plan = _string(data, 'plan', max_length=64, required=False)
    access_mode = data.get('access_mode') or Company.ACCESS_PUBLIC
    if access_mode not in _ACCESS_MODES:
        raise ProvisioningError(400, 'invalid_request', 'access_mode is not supported.')
    owner = data.get('owner')
    if not isinstance(owner, dict):
        raise ProvisioningError(400, 'invalid_request', 'owner is required.')
    subject = _string(owner, 'subject', max_length=255)
    email = normalize_oauth_email(_string(owner, 'email', max_length=254))
    if '@' not in email:
        raise ProvisioningError(400, 'invalid_request', 'owner.email is invalid.')
    if owner.get('email_verified') is not True:
        raise ProvisioningError(403, 'email_not_verified', 'The owner email is not verified.')
    full_name = owner.get('name') if isinstance(owner.get('name'), str) else ''

    existing = ProvisionedCompany.objects.filter(global_company_id=global_id).first()
    if existing is not None:
        raise ProvisioningError(
            409, 'company_exists', 'A company with this global_company_id exists.', {'id': str(existing.company_id)}
        )
    user, created = _owner_user(subject=subject, email=email, full_name=full_name)
    company = Company(name=name, slug=_unique_slug(name), access_mode=access_mode)
    company.save()
    ProvisionedCompany.objects.create(company=company, global_company_id=global_id, plan=plan)
    set_company_access(company, user, enabled=True)
    company.owners.add(user)
    for base_url in getattr(settings, 'PROVISIONING_DEFAULT_REDIRECTS', []) or []:
        CompanyOAuthRedirect.objects.get_or_create(company=company, base_url=base_url, defaults={'is_active': True})
    if created:
        from apps.actions.user_hooks import emit_user_account_created

        emit_user_account_created(company, user, source='provisioning')
    row = ProvisionedCompany.objects.select_related('company').get(company=company)
    return Response(_detail(row), status=201)


def _owner_user(*, subject: str, email: str, full_name: str):
    """Owner linked by global subject. Never staff, never sets staff flags."""
    issuer = _global_issuer()
    link = UpstreamAccount.objects.select_related('user').filter(issuer=issuer, sub=subject).first()
    if link is not None:
        user = link.user
        created = False
    else:
        user = User.objects.filter(email__iexact=email).order_by('pk').first()
        created = user is None
        if user is None:
            user = create_unprivileged_user(email=email, full_name=full_name)
        elif UpstreamAccount.objects.filter(user=user, issuer=issuer).exists():
            raise ProvisioningError(409, 'subject_mismatch', 'The owner email is linked to another subject.')
    if not user.is_active:
        raise ProvisioningError(409, 'user_inactive', 'The owner account is inactive.')
    if is_staff_account(user):
        raise ProvisioningError(409, 'user_is_staff', 'Staff accounts cannot be provisioned as owners.')
    if link is None:
        UpstreamAccount.objects.create(user=user, issuer=issuer, sub=subject, email=email)
    return user, created


def _unique_slug(name: str) -> str:
    base = (slugify(name) or 'company')[:200]
    slug = base
    suffix = 1
    while Company.objects.filter(slug=slug).exists():
        suffix += 1
        slug = f'{base}-{suffix}'
    return slug


def _update(row: ProvisionedCompany, data: dict) -> Response:
    if not data or set(data) - {'name', 'status'}:
        raise ProvisioningError(400, 'invalid_request', 'Only name and status can be changed.')
    if 'name' in data:
        row.company.name = _string(data, 'name', max_length=255)
        row.company.save(update_fields=['name'])
    if 'status' in data:
        status = data.get('status')
        if status not in {ProvisionedCompany.STATUS_ACTIVE, ProvisionedCompany.STATUS_SUSPENDED}:
            raise ProvisioningError(400, 'invalid_request', 'status must be active or suspended.')
        if row.status == ProvisionedCompany.STATUS_DELETING:
            raise ProvisioningError(409, 'company_deleting', 'The company is scheduled for deletion.')
        row.status = status
        row.save(update_fields=['status', 'updated_at'])
    return Response(_detail(row))


def _put_limits(row: ProvisionedCompany, data: dict) -> Response:
    version = data.get('version')
    limits = data.get('limits')
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ProvisioningError(400, 'invalid_request', 'version must be a positive integer.')
    cleaned = clean_limits(limits)
    if version < row.limits_version:
        raise ProvisioningError(409, 'stale_version', 'A newer limits version is stored.')
    CompanyPlan.objects.update_or_create(company=row.company, defaults={'limits': cleaned})
    row.limits_version = version
    row.save(update_fields=['limits_version', 'updated_at'])
    return Response({'id': str(row.company_id), 'version': version, 'limits': cleaned})


def _schedule_deletion(row: ProvisionedCompany) -> Response:
    """Mark for deletion. Data stays until a later purge job; nothing is removed here."""
    if row.status != ProvisionedCompany.STATUS_DELETING:
        row.status = ProvisionedCompany.STATUS_DELETING
        row.deletion_requested_at = timezone.now()
        row.save(update_fields=['status', 'deletion_requested_at', 'updated_at'])
    return Response(_summary(row), status=202)


def clean_limits(value) -> dict:
    if not isinstance(value, dict):
        raise ProvisioningError(400, 'invalid_request', 'limits must be an object.')
    if len(json.dumps(value)) > 4000:
        raise ProvisioningError(400, 'invalid_request', 'limits is too large.')
    cleaned: dict = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ProvisioningError(400, 'invalid_request', 'Invalid limits key.')
        if item is None or isinstance(item, (bool, int)) or (isinstance(item, str) and len(item) <= 200):
            cleaned[key] = item
        else:
            raise ProvisioningError(400, 'invalid_request', 'Limit values must be strings, integers, booleans or null.')
    return cleaned
