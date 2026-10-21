"""Provider-role calls that push a company, its owner, or plan limits."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import requests
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.federation.http import FederationView

from apps.actions.ssrf import SSRFError, resolve_webhook_endpoint
from apps.authapi.oauth_user import normalize_oauth_email
from apps.companies.models import Company
from apps.federation.events import emit_plan_pushed, emit_provisioning_completed
from apps.federation.role import is_global
from apps.federation.session import email_is_verified
from apps.federation.signing import TokenError, new_jti, sign_rs256, unix_now

logger = logging.getLogger(__name__)


def _disabled():
    return Response(status=404)


class _StaffProvisionView(FederationView):
    permission_classes = [IsAuthenticated]

    def _staff(self, request):
        if not is_global():
            return None, _disabled()
        if not getattr(request.user, 'is_staff', False):
            return None, Response({'error': 'Forbidden'}, status=403)
        return request.user, None


class ProvisionOutboundView(_StaffProvisionView):
    def post(self, request):
        user, error = self._staff(request)
        if error:
            return error
        try:
            target = _target(request.data)
            owner_email = normalize_oauth_email(str(request.data.get('owner_email') or ''))
            company_name = str(request.data.get('company_name') or '').strip()
            company_slug = str(request.data.get('company_slug') or '').strip()
            idempotency_key = str(request.data.get('idempotency_key') or '').strip()
        except ValueError as exc:
            return Response({'error': str(exc), 'error_code': 'invalid_request'}, status=400)
        if not owner_email or '@' not in owner_email or not company_name or not idempotency_key:
            return Response({'error': 'company_name, owner_email, and idempotency_key are required.'}, status=400)
        from django.contrib.auth import get_user_model

        owner = get_user_model().objects.filter(email__iexact=owner_email).order_by('pk').first()
        if owner is None or not email_is_verified(owner):
            return Response(
                {'error': 'The owner email is not verified on this instance.', 'error_code': 'email_not_verified'},
                status=403,
            )
        full_name = owner.get_full_name()
        claims = {
            'company': {'name': company_name, 'slug': company_slug or company_name},
            'owner': {'email': owner_email, 'name': full_name},
            'email_verified': True,
        }
        plan = request.data.get('plan')
        if plan is not None:
            if not isinstance(plan, dict):
                return Response({'error': 'plan must be an object.'}, status=400)
            claims['plan'] = plan
        return _send(
            request,
            target=target,
            path='/api/v1/provisioning/companies',
            claims=claims,
            idempotency_key=idempotency_key,
            on_success=lambda: _emit(request, emit_provisioning_completed, company_slug or company_name, target),
        )


class PlanOutboundView(_StaffProvisionView):
    def post(self, request):
        _user, error = self._staff(request)
        if error:
            return error
        try:
            target = _target(request.data)
        except ValueError as exc:
            return Response({'error': str(exc), 'error_code': 'invalid_request'}, status=400)
        slug = str(request.data.get('company_slug') or '').strip()
        plan = request.data.get('plan')
        idempotency_key = str(request.data.get('idempotency_key') or '').strip()
        if not slug or not isinstance(plan, dict) or not idempotency_key:
            return Response({'error': 'company_slug, plan, and idempotency_key are required.'}, status=400)
        return _send(
            request,
            target=target,
            path='/api/v1/provisioning/plans',
            claims={'company_slug': slug, 'plan': plan},
            idempotency_key=idempotency_key,
            on_success=lambda: _emit(request, emit_plan_pushed, slug, target),
        )


def _send(request, *, target: str, path: str, claims: dict, idempotency_key: str, on_success) -> Response:
    audience = str(request.data.get('audience') or '').strip().rstrip('/')
    if not audience:
        return Response({'error': 'audience is required.'}, status=400)
    now = unix_now()
    assertion = {
        'iss': (settings.JWT_ISSUER or '').rstrip('/'),
        'aud': audience,
        'iat': now,
        'nbf': now,
        'exp': now + 60,
        'jti': new_jti(),
        'idempotency_key': idempotency_key,
        **claims,
    }
    if not assertion['iss']:
        return Response({'error': 'JWT_ISSUER is not configured.'}, status=500)
    try:
        token = sign_rs256(assertion)
        _reject_private(target)
        response = requests.post(
            f'{target.rstrip("/")}{path}',
            headers={'Authorization': f'Bearer {token}', 'Idempotency-Key': idempotency_key},
            timeout=10,
            allow_redirects=False,
        )
    except TokenError:
        return Response({'error': 'Signing key is not configured.'}, status=500)
    except (SSRFError, requests.RequestException) as exc:
        logger.warning('provisioning delivery failed: %s', exc.__class__.__name__)
        return Response({'error': 'The relying party could not be reached.', 'error_code': 'delivery_failed'}, status=502)
    if response.status_code in {200, 201}:
        on_success()
    try:
        body = response.json()
    except ValueError:
        body = {'error': 'relying_party_error'}
    return Response(body, status=response.status_code)


def _emit(request, emitter, slug: str, target: str) -> None:
    raw = request.data.get('webhook_company_id')
    if raw in (None, ''):
        return
    try:
        company = Company.objects.get(pk=int(raw))
    except (Company.DoesNotExist, TypeError, ValueError):
        return
    emitter(company=company, client_slug=slug, region_host=urlsplit(target).hostname or '')


def _target(data) -> str:
    if not isinstance(data, dict):
        raise ValueError('JSON object required.')
    raw = str(data.get('region_base_url') or '').strip().rstrip('/')
    parts = urlsplit(raw)
    allow_http = bool(settings.DEBUG)
    schemes = {'https', 'http'} if allow_http else {'https'}
    if parts.scheme not in schemes or not parts.netloc or parts.path not in {'', '/'}:
        raise ValueError('region_base_url must be an origin.')
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError('region_base_url must be an origin.')
    return f'{parts.scheme}://{parts.netloc}'


def _reject_private(url: str) -> None:
    resolve_webhook_endpoint(url + '/', allow_private=bool(getattr(settings, 'ACTIONS_WEBHOOK_ALLOW_PRIVATE', False)))
