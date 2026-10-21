"""Relying-party provisioning API: signed assertions and idempotency keys."""

from __future__ import annotations

import hashlib
import json
import logging
import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils.text import slugify
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from apps.federation.http import FederationView

from apps.authapi.oauth_user import normalize_oauth_email
from apps.companies.access import set_company_access
from apps.companies.models import Company
from apps.federation.models import AssertionUse, CompanyPlan, ProvisioningReceipt
from apps.federation.role import is_region
from apps.federation.signing import TokenError, issuer, verify_pinned
from apps.federation.users import create_unprivileged_user

logger = logging.getLogger(__name__)
User = get_user_model()
_KEY_RE = re.compile(r'^[A-Za-z0-9._:-]{8,200}$')


def _disabled():
    return Response(status=404)


class ProvisionCompanyView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        if not is_region():
            return _disabled()
        claims, error = _authenticate(request)
        if error:
            return error
        try:
            body = _company_body(claims)
        except ValueError as exc:
            return _error(str(exc), 'invalid_assertion', 400)
        if claims.get('email_verified') is not True:
            return _error('The upstream email is not verified.', 'email_not_verified', 403)
        return _apply(claims, body, lambda: _create_company_and_owner(body))


class ProvisionPlanView(FederationView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        if not is_region():
            return _disabled()
        claims, error = _authenticate(request)
        if error:
            return error
        try:
            slug = _slug(claims.get('company_slug') or '')
            limits = clean_limits(claims.get('plan'))
        except ValueError as exc:
            return _error(str(exc), 'invalid_assertion', 400)
        body = {'company_slug': slug, 'plan': limits, 'idempotency_key': claims['idempotency_key']}
        return _apply(claims, body, _plan_apply(slug, limits))


class CompanyPlanView(FederationView):
    permission_classes = [IsAuthenticated]

    def get(self, request, company_id: int):
        if not is_region():
            return _disabled()
        company = Company.objects.filter(pk=company_id, members=request.user).first()
        if company is None:
            return Response({'error': 'Not found.'}, status=404)
        plan = CompanyPlan.objects.filter(company=company).first()
        return Response({'company_id': company.pk, 'limits': plan.limits if plan else {}})


def clean_limits(value) -> dict:
    if not isinstance(value, dict) or not value:
        raise ValueError('plan must be an object.')
    if len(json.dumps(value)) > 4000:
        raise ValueError('plan is too large.')
    cleaned: dict = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ValueError('Invalid plan key.')
        if isinstance(item, bool) or (isinstance(item, int) and not isinstance(item, bool)):
            cleaned[key] = item
        elif isinstance(item, str) and len(item) <= 200:
            cleaned[key] = item
        else:
            raise ValueError('Plan values must be strings, integers, or booleans.')
    return cleaned


def _plan_apply(slug: str, limits: dict):
    def apply():
        company = Company.objects.filter(slug=slug).first()
        if company is None:
            return None
        CompanyPlan.objects.update_or_create(company=company, defaults={'limits': limits})
        return {'company_id': company.pk, 'slug': company.slug, 'limits': limits}

    return apply


def _create_company_and_owner(body: dict) -> dict:
    company = Company.objects.filter(slug=body['slug']).first()
    if company is None:
        company = Company(name=body['name'], slug=body['slug'], access_mode=Company.ACCESS_INVITE)
        company.save()
    elif company.name != body['name']:
        company.name = body['name']
        company.save(update_fields=['name'])
    user = User.objects.filter(email__iexact=body['email']).order_by('pk').first()
    created = False
    if user is None:
        user = create_unprivileged_user(email=body['email'], full_name=body['full_name'])
        created = True
    elif not user.is_active:
        raise ValueError('user_inactive')
    set_company_access(company, user, enabled=True)
    company.owners.add(user)
    if body['plan'] is not None:
        CompanyPlan.objects.update_or_create(company=company, defaults={'limits': body['plan']})
    from apps.actions.user_hooks import emit_user_account_created

    if created:
        emit_user_account_created(company, user, source='provisioning')
    user.refresh_from_db()
    return {
        'company_id': company.pk,
        'slug': company.slug,
        'owner_user_id': user.pk,
        'created': created,
    }


def _apply(claims: dict, body: dict, work) -> Response:
    key = claims['idempotency_key']
    body_hash = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
    jti = str(claims.get('jti') or '')
    existing = ProvisioningReceipt.objects.filter(idempotency_key=key).first()
    if existing is not None and existing.body_hash != body_hash:
        return _error('Idempotency key was already used for a different request.', 'idempotency_conflict', 409)
    try:
        with transaction.atomic():
            use = AssertionUse.objects.create(jti=jti, idempotency_key=key)
            del use
            if existing is not None:
                return Response(existing.response_body, status=existing.status_code)
            result = work()
            if result is None:
                raise LookupError('company_not_found')
            ProvisioningReceipt.objects.create(
                idempotency_key=key,
                body_hash=body_hash,
                status_code=200,
                response_body=result,
            )
    except IntegrityError:
        return _replay_or_reject(jti, key, body_hash)
    except LookupError:
        return _error('Company not found.', 'company_not_found', 404)
    except ValueError as exc:
        code = str(exc)
        if code == 'user_inactive':
            return _error('The user account is inactive.', 'user_inactive', 409)
        return _error('Could not provision the company.', 'invalid_assertion', 400)
    return Response(result, status=200)


def _replay_or_reject(jti: str, key: str, body_hash: str) -> Response:
    receipt = ProvisioningReceipt.objects.filter(idempotency_key=key).first()
    previous = AssertionUse.objects.filter(jti=jti).first()
    if receipt is not None and receipt.body_hash == body_hash and (
        previous is None or previous.idempotency_key == key
    ):
        if previous is None:
            AssertionUse.objects.get_or_create(jti=jti, defaults={'idempotency_key': key})
        return Response(receipt.response_body, status=receipt.status_code)
    logger.info('rejected replayed provisioning assertion')
    return _error('Assertion was already used.', 'assertion_replayed', 401)


def _authenticate(request):
    if not _upstream_configured():
        return None, _disabled()
    token = _bearer(request)
    header_key = (request.headers.get('Idempotency-Key') or '').strip()
    if not token or not _KEY_RE.fullmatch(header_key):
        return None, _error('A signed assertion and Idempotency-Key are required.', 'invalid_assertion', 401)
    audience = issuer()
    if not audience:
        return None, _error('JWT_ISSUER is not configured.', 'invalid_assertion', 500)
    try:
        claims = verify_pinned(
            token,
            audience=audience,
            issuer_url=settings.GLOBAL_ISSUER_URL,
            require=['exp', 'iat', 'iss', 'aud', 'jti'],
        )
    except TokenError:
        return None, _error('Assertion was rejected.', 'invalid_assertion', 401)
    if claims.get('idempotency_key') != header_key:
        return None, _error('Idempotency-Key does not match the assertion.', 'invalid_assertion', 401)
    try:
        issued = int(claims['iat'])
        expires = int(claims['exp'])
    except (KeyError, TypeError, ValueError):
        return None, _error('Assertion was rejected.', 'invalid_assertion', 401)
    if expires - issued > 120:
        return None, _error('Assertion lifetime is too long.', 'invalid_assertion', 401)
    aud = claims.get('aud')
    if aud != audience and aud != [audience]:
        return None, _error('Assertion was rejected.', 'invalid_assertion', 401)
    return claims, None


def _company_body(claims: dict) -> dict:
    company = claims.get('company')
    owner = claims.get('owner')
    if not isinstance(company, dict) or not isinstance(owner, dict):
        raise ValueError('invalid_assertion')
    name = str(company.get('name') or '').strip()
    slug = _slug(company.get('slug') or name)
    email = normalize_oauth_email(str(owner.get('email') or ''))
    if not name or len(name) > 255 or not email or '@' not in email:
        raise ValueError('invalid_assertion')
    full_name = owner.get('name') if isinstance(owner.get('name'), str) else ''
    plan = None
    if 'plan' in claims and claims.get('plan') is not None:
        plan = clean_limits(claims.get('plan'))
    return {
        'name': name,
        'slug': slug,
        'email': email,
        'full_name': full_name[:300],
        'plan': plan,
        'idempotency_key': claims['idempotency_key'],
    }


def _slug(value) -> str:
    slug = slugify(str(value or ''))[:255]
    if not slug:
        raise ValueError('invalid_assertion')
    return slug


def _bearer(request) -> str:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        return ''
    return header.split(' ', 1)[1].strip()


def _upstream_configured() -> bool:
    document = getattr(settings, 'GLOBAL_JWKS', {}) or {}
    return bool(
        (getattr(settings, 'GLOBAL_ISSUER_URL', '') or '').strip()
        and isinstance(document, dict)
        and document.get('keys')
    )


def _error(message: str, code: str, status: int) -> Response:
    return Response({'error': message, 'error_code': code}, status=status)
