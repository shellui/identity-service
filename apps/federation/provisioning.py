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
from apps.companies.access import normalize_allowed_domains, set_company_access
from apps.companies.models import Company, CompanyMembership, CompanyOAuthRedirect
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
_PATCH_KEYS = {'name', 'status', 'access_mode', 'allowed_email_domains'}
_MEMBER_ROLES = {'owner', 'staff'}


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


class ProvisioningCompanyMembersView(_ProvisioningView):
    def post(self, request, company_id: int):
        return self._run(
            request,
            lambda: _add_member(_provisioned(company_id), self._body(request)),
            write=True,
        )


class ProvisioningCompanyMemberView(_ProvisioningView):
    def patch(self, request, company_id: int, global_subject: str):
        return self._run(
            request,
            lambda: _set_member_role(_provisioned(company_id), global_subject, self._body(request)),
            write=True,
        )

    def delete(self, request, company_id: int, global_subject: str):
        return self._run(
            request,
            lambda: _remove_member(_provisioned(company_id), global_subject),
            write=True,
        )


class ProvisioningTransferOwnershipView(_ProvisioningView):
    def post(self, request, company_id: int):
        return self._run(
            request,
            lambda: _transfer_ownership(_provisioned(company_id), self._body(request)),
            write=True,
        )


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
    return {
        **_summary(row),
        'access_mode': row.company.access_mode,
        'allowed_email_domains': list(row.company.allowed_email_domains or []),
        'owners': [{'subject': sub} for sub in subjects],
    }


def _global_issuer() -> str:
    return (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip().rstrip('/')


def _string(data: dict, key: str, *, max_length: int, required: bool = True) -> str:
    value = data.get(key)
    if value is None and not required:
        return ''
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > max_length:
        raise ProvisioningError(400, 'invalid_request', f'{key} is required (max {max_length} characters).')
    return value.strip()


def _require_access_mode(mode) -> None:
    if not isinstance(mode, str) or mode not in _ACCESS_MODES:
        raise ProvisioningError(400, 'invalid_request', 'access_mode must be public, domain, or invite.')


def _email_domains(value) -> list[str]:
    """Lowercase domains with no ``@``. Rejects anything that is not a domain string."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProvisioningError(400, 'invalid_request', 'allowed_email_domains must be a list of domains.')
    raw: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ProvisioningError(400, 'invalid_request', 'allowed_email_domains must be a list of domains.')
        domain = item.strip().lower().lstrip('@').rstrip('.')
        if (
            not domain
            or '@' in domain
            or '/' in domain
            or any(ch.isspace() for ch in domain)
            or len(domain) > 253
        ):
            raise ProvisioningError(
                400,
                'invalid_request',
                'allowed_email_domains must be lowercase domains without @.',
            )
        raw.append(domain)
    return normalize_allowed_domains(raw)


def _require_domains_for_mode(mode: str, domains: list[str]) -> None:
    if mode == Company.ACCESS_DOMAIN and not domains:
        raise ProvisioningError(400, 'invalid_request', 'Domain access mode needs at least one email domain.')


def _create(data: dict) -> Response:
    global_id = _string(data, 'global_company_id', max_length=64)
    name = _string(data, 'name', max_length=255)
    plan = _string(data, 'plan', max_length=64, required=False)
    access_mode = data.get('access_mode') or Company.ACCESS_PUBLIC
    _require_access_mode(access_mode)
    domains = _email_domains(data.get('allowed_email_domains')) if 'allowed_email_domains' in data else []
    _require_domains_for_mode(access_mode, domains)
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
    company = Company(
        name=name,
        slug=_unique_slug(name),
        access_mode=access_mode,
        allowed_email_domains=domains,
    )
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
    if not data or set(data) - _PATCH_KEYS:
        raise ProvisioningError(
            400,
            'invalid_request',
            'Only name, status, access_mode, and allowed_email_domains can be changed.',
        )
    company = row.company
    company_fields: list[str] = []
    if 'name' in data:
        company.name = _string(data, 'name', max_length=255)
        company_fields.append('name')
    if 'access_mode' in data or 'allowed_email_domains' in data:
        mode = data.get('access_mode') if 'access_mode' in data else company.access_mode
        _require_access_mode(mode)
        if 'allowed_email_domains' in data:
            domains = _email_domains(data.get('allowed_email_domains'))
        else:
            domains = list(company.allowed_email_domains or [])
        _require_domains_for_mode(mode, domains)
        if 'access_mode' in data:
            company.access_mode = mode
            company_fields.append('access_mode')
        if 'allowed_email_domains' in data:
            company.allowed_email_domains = domains
            company_fields.append('allowed_email_domains')
    if company_fields:
        company.save(update_fields=company_fields)
    if 'status' in data:
        status = data.get('status')
        if status not in {ProvisionedCompany.STATUS_ACTIVE, ProvisionedCompany.STATUS_SUSPENDED}:
            raise ProvisioningError(400, 'invalid_request', 'status must be active or suspended.')
        if row.status == ProvisionedCompany.STATUS_DELETING:
            raise ProvisioningError(409, 'company_deleting', 'The company is scheduled for deletion.')
        row.status = status
        row.save(update_fields=['status', 'updated_at'])
    return Response(_detail(row))


def _member_role(company: Company, user) -> str:
    if company.owners.filter(pk=user.pk).exists():
        return 'owner'
    return 'staff'


def _member_body(user, subject: str, role: str) -> dict:
    return {
        'global_subject': subject,
        'email': user.email or '',
        'name': (user.get_full_name() or '').strip(),
        'role': role,
        'status': 'active',
    }


def _member_user(company: Company, subject: str):
    link = (
        UpstreamAccount.objects.select_related('user')
        .filter(issuer=_global_issuer(), sub=subject)
        .first()
    )
    if link is None or not CompanyMembership.objects.filter(company=company, user=link.user).exists():
        raise ProvisioningError(404, 'not_found', 'Member not found.')
    return link.user


def _add_member(row: ProvisionedCompany, data: dict) -> Response:
    email = normalize_oauth_email(_string(data, 'email', max_length=254))
    if '@' not in email:
        raise ProvisioningError(400, 'invalid_request', 'email is invalid.')
    role = data.get('role') or 'staff'
    if role not in _MEMBER_ROLES:
        raise ProvisioningError(400, 'invalid_request', 'role must be owner or staff.')
    subject = _string(data, 'global_subject', max_length=255)
    full_name = data.get('name') if isinstance(data.get('name'), str) else ''
    if 'name' in data and not isinstance(data.get('name'), str):
        raise ProvisioningError(400, 'invalid_request', 'name must be a string.')
    company = row.company
    issuer = _global_issuer()
    if UpstreamAccount.objects.filter(
        issuer=issuer,
        sub=subject,
        user__company_memberships__company=company,
    ).exists():
        raise ProvisioningError(409, 'member_exists', 'That person is already a member.')
    existing = User.objects.filter(email__iexact=email).order_by('pk').first()
    if existing is not None and CompanyMembership.objects.filter(company=company, user=existing).exists():
        raise ProvisioningError(409, 'member_exists', 'That person is already a member.')
    user, _created = _owner_user(subject=subject, email=email, full_name=full_name)
    set_company_access(company, user, enabled=True)
    if role == 'owner':
        company.owners.add(user)
    return Response(_member_body(user, subject, _member_role(company, user)), status=201)


def _set_member_role(row: ProvisionedCompany, subject: str, data: dict) -> Response:
    if set(data) - {'role'}:
        raise ProvisioningError(400, 'invalid_request', 'Only role can be changed.')
    role = data.get('role')
    if role not in _MEMBER_ROLES:
        raise ProvisioningError(400, 'invalid_request', 'role must be owner or staff.')
    company = row.company
    user = _member_user(company, subject)
    with transaction.atomic():
        locked = Company.objects.select_for_update().get(pk=company.pk)
        is_owner = locked.owners.filter(pk=user.pk).exists()
        if is_owner and role != 'owner' and locked.owners.count() <= 1:
            raise ProvisioningError(409, 'last_owner', 'A project needs at least one owner.')
        if role == 'owner':
            locked.owners.add(user)
        elif is_owner:
            locked.owners.remove(user)
    return Response(_member_body(user, subject, _member_role(company, user)))


def _remove_member(row: ProvisionedCompany, subject: str) -> Response:
    company = row.company
    user = _member_user(company, subject)
    with transaction.atomic():
        locked = Company.objects.select_for_update().get(pk=company.pk)
        if locked.owners.filter(pk=user.pk).exists() and locked.owners.count() <= 1:
            raise ProvisioningError(409, 'last_owner', 'A project needs at least one owner.')
        locked.owners.remove(user)
        CompanyMembership.objects.filter(company=locked, user=user).delete()
        _revoke_member_credentials(locked, user)
    return Response({'global_subject': subject, 'status': 'removed'})


def _transfer_ownership(row: ProvisionedCompany, data: dict) -> Response:
    if set(data) - {'global_subject', 'from_subject'}:
        raise ProvisioningError(400, 'invalid_request', 'global_subject and from_subject are required.')
    target_subject = _string(data, 'global_subject', max_length=255)
    from_subject = _string(data, 'from_subject', max_length=255)
    if target_subject == from_subject:
        raise ProvisioningError(400, 'invalid_request', 'Choose another member.')
    company = row.company
    target = _member_user(company, target_subject)
    source = _member_user(company, from_subject)
    with transaction.atomic():
        locked = Company.objects.select_for_update().get(pk=company.pk)
        if not locked.owners.filter(pk=source.pk).exists():
            raise ProvisioningError(400, 'invalid_request', 'from_subject is not an owner.')
        locked.owners.add(target)
        locked.owners.remove(source)
        if locked.owners.count() < 1:
            raise ProvisioningError(409, 'last_owner', 'A project needs at least one owner.')
    return Response(
        {
            'global_subject': target_subject,
            'from_subject': from_subject,
            'owners': [
                {'subject': sub}
                for sub in UpstreamAccount.objects.filter(
                    user_id__in=company.owners.values_list('pk', flat=True),
                    issuer=_global_issuer(),
                )
                .order_by('pk')
                .values_list('sub', flat=True)
            ],
        }
    )


def _revoke_member_credentials(company: Company, user) -> None:
    """Drop this company's refresh sessions and personal access tokens for ``user``."""
    from apps.authapi.models import PersonalAccessToken, RefreshTokenSession

    now = timezone.now()
    RefreshTokenSession.objects.filter(user=user, company=company, revoked_at__isnull=True).update(revoked_at=now)
    PersonalAccessToken.objects.filter(user=user, company=company, revoked_at__isnull=True).update(revoked_at=now)


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
    """Flag for deletion. The purge job (every 60 seconds) removes the company and its data."""
    from apps.companies.deletion import request_company_deletion

    request_company_deletion(row.company)
    row.refresh_from_db()
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
