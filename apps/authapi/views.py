import json
import logging
import uuid
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseRedirect
from django.utils.dateparse import parse_datetime
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.contrib.sites.models import Site
from django.db import IntegrityError
from django.db.models import Count, Q
from django.shortcuts import render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from allauth.socialaccount.models import SocialApp, SocialAccount
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.permissions import AllowAny

from .permissions import ShellUIPermission
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .tokens import ShellUIAccessToken, ShellUIRefreshToken

from . import metrics as auth_metrics
from apps.companies.models import Company, CompanyGroup, CompanyOAuthClient, CompanyOAuthRedirect
from apps.companies.access import (
    JoinDecision,
    apply_company_join,
    is_company_access_enabled,
    notify_user_access_enabled,
    set_company_access,
)
from apps.companies.redirect_allowlist import (
    append_oauth_error_params,
    loopback_client_bounce_url_for_oauth_error,
    validate_redirect_to_for_company,
)
from .renderers import PrometheusTextRenderer
from .login_audit import oauth_provider_redirect_uri, record_login_event
from .oauth_state import build_oauth_state, parse_oauth_state
from .oauth_confirm import build_oauth_confirm_token, parse_oauth_confirm_token
from .authentication import ShellUIJWTAuthentication
from .models import LoginEvent, PersonalAccessToken, UserPreference
from .user_activity import touch_user_last_seen
from .oauth import (
    SUPPORTED_OAUTH_PROVIDERS,
    build_authorize_url,
    exchange_code_for_token,
    fetch_provider_userinfo,
    get_provider_config,
)
from .serializers import (
    ProviderAuthorizeSerializer,
    ProviderCallbackSerializer,
    ShellUIOAuthExchangeSerializer,
    ShellUIRefreshTokenSerializer,
    ShellUIOpenAPISerializer,
    ShellUIAdminGroupCreateSerializer,
    ShellUIAdminGroupUpdateSerializer,
    ShellUIAdminOAuthClientCreateSerializer,
    ShellUIAdminOAuthSocialAppCreateSerializer,
    ShellUIAdminOAuthSocialAppUpdateSerializer,
    ShellUIAdminOAuthClientUpdateSerializer,
    ShellUIAdminOAuthRedirectCreateSerializer,
    ShellUIAdminOAuthRedirectUpdateSerializer,
    ShellUIPersonalAccessTokenCreateSerializer,
    ShellUIAdminUserUpdateSerializer,
    UserPreferenceSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)
logger = logging.getLogger(__name__)

# Client-supplied user_metadata merges cannot set these; they are derived from Django / company state.
_SHELLUI_JWT_PRIVILEGED_METADATA_KEYS = frozenset({'is_staff', 'is_company_owner', 'groups'})


def _is_user_company_owner(user: User, company: Company) -> bool:
    return company.owners.filter(pk=user.pk).exists()


def _notify_user_logged_in_for_oauth(request, user: User) -> None:
    """
    OAuth success paths do not call django.contrib.auth.login(), so Django never emits
    user_logged_in and last_login stays stale. Fire the same signal so built-in
    update_last_login runs (and any other user_logged_in receivers).
    """
    user_logged_in.send(sender=user.__class__, request=request, user=user)
    touch_user_last_seen(user)


def _last_seen_at_for_user(user: User) -> str | None:
    """ISO 8601 timestamp from UserActivity, or None if never recorded."""
    try:
        ts = user.activity.last_seen_at
    except ObjectDoesNotExist:
        return None
    if ts is None:
        return None
    return ts.isoformat()


def _enrich_user_metadata_avatar(user: User, user_metadata: dict) -> None:
    """
    Fill user_metadata['avatar_url'] from cache, then linked SocialAccount extra_data (GitHub
    avatar_url, etc.). SPA OAuth (SocialLoginView) used to skip caching; this also fixes GET /user.
    """
    explicit = _normalize_avatar_url(user_metadata.get('avatar_url'))
    user_metadata['avatar_url'] = _resolve_avatar_url_for_jwt(user, explicit)


def _user_preferences_payload(user: User) -> dict:
    preference, _ = UserPreference.objects.get_or_create(user=user)
    return {
        'themeName': preference.theme_name,
        'language': preference.language,
        'region': preference.region,
        'colorScheme': preference.color_scheme,
    }


def _user_group_names(user: User, company: Company) -> list[str]:
    return list(
        CompanyGroup.objects.filter(company=company, members=user).values_list('name', flat=True).order_by('name')
    )


def _admin_user_group_rows(user: User, company: Company) -> list[dict]:
    return list(
        CompanyGroup.objects.filter(company=company, members=user).values('id', 'name').order_by('name')
    )


def _extract_user_data(provider: str, userinfo: dict, access_token: str) -> tuple[str, str, str, str | None]:
    provider_id = str(
        userinfo.get('id')
        or userinfo.get('sub')
        or userinfo.get('userPrincipalName')
        or userinfo.get('mail')
    )
    email = userinfo.get('email') or userinfo.get('mail') or userinfo.get('userPrincipalName')
    full_name = userinfo.get('name') or userinfo.get('displayName') or ''

    if provider == 'github' and not email:
        req = urllib.request.Request(
            'https://api.github.com/user/emails',
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            emails = json.loads(response.read().decode('utf-8'))
        primary = next((item for item in emails if item.get('primary')), None)
        if primary:
            email = primary.get('email')

    if not email:
        email = f'{provider_id}@{provider}.local'

    if not full_name:
        full_name = email.split('@')[0]

    avatar_url = userinfo.get('avatar_url') or userinfo.get('picture') or userinfo.get('photo')
    if not isinstance(avatar_url, str) or not avatar_url.strip():
        avatar_url = None

    return provider_id, email.lower(), full_name, avatar_url


def _normalize_avatar_url(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _resolve_avatar_url_for_jwt(user: User, explicit: str | None = None) -> str | None:
    """Resolve profile image URL for Shellui JWT user_metadata (callback, refresh, rotation)."""
    url = _normalize_avatar_url(explicit)
    if url:
        return url
    cache_key = f"shellui:user_metadata:{user.id}"
    cached = cache.get(cache_key) or {}
    url = _normalize_avatar_url(cached.get('avatar_url') if isinstance(cached, dict) else None)
    if url:
        return url
    for account in SocialAccount.objects.filter(user=user):
        extra = account.extra_data or {}
        if not isinstance(extra, dict):
            continue
        url = _normalize_avatar_url(
            extra.get('avatar_url') or extra.get('picture') or extra.get('photo')
        )
        if url:
            return url
    return None


def _resolve_auth_provider_for_jwt(
    user: User,
    oauth_provider: str | None = None,
    prior_auth_provider: str | None = None,
) -> str:
    """OAuth callback provider wins; on refresh, keep prior JWT provider (e.g. github), not 'refresh'."""
    for candidate in (oauth_provider, prior_auth_provider):
        if isinstance(candidate, str) and candidate.strip():
            p = candidate.strip().lower()
            if p != 'refresh':
                return p
    account = SocialAccount.objects.filter(user=user).order_by('pk').first()
    if account and getattr(account, 'provider', None):
        return str(account.provider).lower()
    return 'refresh'


def _issue_tokens(user: User, company: Company) -> dict:
    user_payload = {
        'id': user.id,
        'email': user.email,
        'username': user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
    }
    refresh = ShellUIRefreshToken.for_user(user)
    refresh['user'] = user_payload
    refresh['company_id'] = company.id
    access = refresh.access_token
    access['user'] = user_payload
    access['company_id'] = company.id
    return {
        'refresh': str(refresh),
        'access': str(access),
        'user': user_payload,
    }


def _parse_company_oauth_client_id(value: str | None) -> int | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _company_oauth_clients(company: Company) -> list[CompanyOAuthClient]:
    return list(
        CompanyOAuthClient.objects.filter(company=company, is_active=True)
        .exclude(social_app__client_id='')
        .exclude(social_app__secret='')
        .select_related('social_app')
        .order_by('social_app__provider', 'social_app__name', 'id')
    )


def _get_company_oauth_client(
    company: Company,
    provider: str,
    company_oauth_client_id: int | None,
) -> tuple[CompanyOAuthClient | None, str | None]:
    if company_oauth_client_id is None:
        return None, None
    row = (
        CompanyOAuthClient.objects.filter(
            pk=company_oauth_client_id,
            company=company,
            social_app__provider=provider,
            is_active=True,
        )
        .exclude(social_app__client_id='')
        .exclude(social_app__secret='')
        .select_related('social_app')
        .first()
    )
    if row:
        return row, None
    return None, 'Requested company_oauth_client_id is not available for this provider.'


def _enabled_oauth_providers(company: Company) -> list[str]:
    return sorted({str(row.social_app.provider).lower() for row in _company_oauth_clients(company)})


def _supported_oauth_providers() -> list[str]:
    return sorted(SUPPORTED_OAUTH_PROVIDERS)


def _oauth_client_payload(row: CompanyOAuthClient) -> dict:
    social_app_settings = row.social_app.settings or {}
    if not isinstance(social_app_settings, dict):
        social_app_settings = {}
    return {
        'id': row.id,
        'provider': row.social_app.provider,
        'label': row.social_app.name,
        'client_id': row.social_app.client_id,
        'tenant': str(social_app_settings.get('tenant') or ''),
        'social_app_id': row.social_app_id,
        'is_active': row.is_active,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
    }


def _oauth_social_app_payload(company: Company, app: SocialApp) -> dict:
    mapping = (
        CompanyOAuthClient.objects.filter(company=company, social_app=app)
        .order_by('-id')
        .first()
    )
    app_settings = app.settings if isinstance(app.settings, dict) else {}
    return {
        'id': app.id,
        'provider': app.provider,
        'name': app.name,
        'client_id': app.client_id,
        'tenant': str(app_settings.get('tenant') or ''),
        'is_linked': mapping is not None,
        'mapping_id': mapping.id if mapping is not None else None,
        'mapping_is_active': bool(mapping.is_active) if mapping is not None else False,
    }


def _generated_social_app_name(provider: str, company: Company) -> str:
    base = f'{provider}-company-{company.id}'
    candidate = base
    suffix = 2
    while SocialApp.objects.filter(name=candidate).exists():
        candidate = f'{base}-{suffix}'
        suffix += 1
    return candidate


def _issue_shellui_tokens(
    user: User,
    company: Company,
    avatar_url: str | None = None,
    *,
    oauth_provider: str | None = None,
    prior_app_metadata: dict | None = None,
) -> dict:
    refresh = ShellUIRefreshToken.for_user(user)
    preferences = _user_preferences_payload(user)
    resolved_avatar = _resolve_avatar_url_for_jwt(user, avatar_url)
    user_metadata = {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': resolved_avatar,
        'is_staff': bool(user.is_staff),
        'is_company_owner': _is_user_company_owner(user, company),
        'shelluiPreferences': preferences,
        'groups': _user_group_names(user, company),
    }
    app_meta_base = dict(prior_app_metadata) if isinstance(prior_app_metadata, dict) else {}
    prior_provider = app_meta_base.get('provider') if isinstance(app_meta_base.get('provider'), str) else None
    app_meta_base['provider'] = _resolve_auth_provider_for_jwt(
        user,
        oauth_provider=oauth_provider,
        prior_auth_provider=prior_provider,
    )
    app_metadata = app_meta_base
    access = refresh.access_token
    access['email'] = user.email
    access['company_id'] = company.id
    access['user_metadata'] = user_metadata
    access['app_metadata'] = app_metadata
    refresh['user_metadata'] = user_metadata
    refresh['company_id'] = company.id
    refresh['app_metadata'] = app_metadata
    now_ts = int(datetime.now(timezone.utc).timestamp())
    expires_at = int(access['exp'])
    return {
        'access_token': str(access),
        'refresh_token': str(refresh),
        'token_type': 'bearer',
        'expires_in': max(0, expires_at - now_ts),
        'expires_at': expires_at,
    }


def _issue_personal_access_token(
    user: User,
    company: Company,
    *,
    read_only: bool,
    access_global_metrics: bool = False,
    name: str = '',
) -> tuple[PersonalAccessToken, str]:
    pat_id = uuid.uuid4()
    access = ShellUIAccessToken.for_user(user)
    preferences = _user_preferences_payload(user)
    resolved_avatar = _resolve_avatar_url_for_jwt(user, None)
    user_metadata = {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': resolved_avatar,
        'is_staff': bool(user.is_staff),
        'is_company_owner': _is_user_company_owner(user, company),
        'shelluiPreferences': preferences,
        'groups': _user_group_names(user, company),
    }
    access['email'] = user.email
    access['company_id'] = company.id
    access['user_metadata'] = user_metadata
    access['app_metadata'] = {'provider': 'personal_access_token'}
    access['pat_id'] = str(pat_id)
    access['pat_ro'] = bool(read_only)
    access['pat_agm'] = bool(access_global_metrics)
    access.set_exp(lifetime=settings.PERSONAL_ACCESS_TOKEN_LIFETIME)
    jti = access['jti']
    row = PersonalAccessToken.objects.create(
        id=pat_id,
        company=company,
        user=user,
        jti=jti,
        read_only=read_only,
        access_global_metrics=access_global_metrics,
        name=(name or '')[:200],
    )
    return row, str(access)


def _link_social_account(user: User, provider: str, provider_id: str, userinfo: dict) -> None:
    # Persist provider payload in DB so one user can have multiple linked auth methods.
    SocialAccount.objects.update_or_create(
        provider=provider,
        uid=provider_id,
        defaults={
            'user': user,
            'extra_data': userinfo if isinstance(userinfo, dict) else {},
        },
    )


def _build_callback_redirect(redirect_to: str, payload: dict, provider: str) -> str:
    params = {
        'access_token': payload['access_token'],
        'refresh_token': payload['refresh_token'],
        'token_type': payload['token_type'],
        'expires_at': str(payload['expires_at']),
        'expires_in': str(payload['expires_in']),
        'provider': provider,
    }
    return f"{redirect_to}#{urlencode(params)}"


def _provider_display_label(provider: str) -> str:
    labels = {'github': 'GitHub', 'google': 'Google', 'microsoft': 'Microsoft'}
    key = str(provider or '').strip().lower()
    return labels.get(key, key.title() or 'OAuth')


def _build_shellui_authorize_url(
    request,
    *,
    company: Company,
    redirect_to: str,
    provider: str,
    company_oauth_client_id: int | None = None,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
    switch_account: bool = False,
) -> str:
    params: dict[str, str] = {
        'provider': str(provider).strip().lower(),
        'company_id': str(company.id),
        'redirect_to': redirect_to,
    }
    if company_oauth_client_id is not None:
        params['company_oauth_client_id'] = str(company_oauth_client_id)
    tz = (client_timezone or '').strip()
    if tz:
        params['client_timezone'] = tz[:64]
    dev = (client_device_id or '').strip()
    if dev:
        params['client_device_id'] = dev[:128]
    if switch_account:
        params['switch_account'] = '1'
    path = f"{reverse('shellui-authorize')}?{urlencode(params)}"
    return request.build_absolute_uri(path)


def _oauth_method_choices_for_company(
    request,
    company: Company,
    redirect_to: str,
    *,
    current_provider: str | None = None,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
    switch_account: bool = False,
) -> list[dict]:
    current = str(current_provider or '').strip().lower()
    choices: list[dict] = []
    for provider in _enabled_oauth_providers(company):
        choices.append(
            {
                'provider': provider,
                'label': _provider_display_label(provider),
                'url': _build_shellui_authorize_url(
                    request,
                    company=company,
                    redirect_to=redirect_to,
                    provider=provider,
                    client_timezone=client_timezone,
                    client_device_id=client_device_id,
                    switch_account=switch_account and provider == current,
                ),
                'current': provider == current,
            }
        )
    return choices


def _render_oauth_method_select_page(
    request,
    *,
    company: Company,
    redirect_to: str,
    client_timezone: str | None = None,
    client_device_id: str | None = None,
):
    methods = _oauth_method_choices_for_company(
        request,
        company,
        redirect_to,
        client_timezone=client_timezone,
        client_device_id=client_device_id,
    )
    return render(
        request,
        'authapi/oauth_method_select.html',
        {
            'company_name': company.name,
            'methods': methods,
            'multiple_methods': len(methods) > 1,
        },
    )


def _user_display_initials(user: User, full_name: str = '') -> str:
    name = (full_name or user.get_full_name() or user.email or user.get_username() or '?').strip()
    parts = [p for p in name.split() if p]
    if len(parts) >= 2:
        return f'{parts[0][0]}{parts[-1][0]}'.upper()
    return name[:2].upper() if name else '?'


def _finalize_shellui_oauth_login(
    request,
    *,
    user: User,
    company: Company,
    provider: str,
    redirect_to: str,
    avatar_url: str | None,
    client_tz: str = '',
    client_dev: str | None = None,
) -> HttpResponseRedirect:
    _notify_user_logged_in_for_oauth(request, user)
    payload = _issue_shellui_tokens(user, company=company, avatar_url=avatar_url, oauth_provider=provider)
    auth_metrics.record_successful_login(provider, company_id=company.id)
    record_login_event(
        request=request,
        outcome=LoginEvent.OUTCOME_SUCCESS,
        provider=provider,
        user=user,
        company=company,
        client_timezone=client_tz,
        client_device_id=client_dev,
    )
    return HttpResponseRedirect(_build_callback_redirect(redirect_to, payload, provider=provider))


def _render_oauth_confirm_page(
    request,
    *,
    user: User,
    company: Company,
    provider: str,
    redirect_to: str,
    avatar_url: str | None,
    company_oauth_client_id: int | None = None,
    client_tz: str = '',
    client_dev: str | None = None,
    error_message: str | None = None,
):
    confirm_token = build_oauth_confirm_token(
        user_id=user.id,
        company_id=company.id,
        provider=provider,
        redirect_to=redirect_to,
        avatar_url=avatar_url,
        company_oauth_client_id=company_oauth_client_id,
        client_timezone=client_tz or None,
        client_device_id=client_dev,
    )
    confirm_url = request.build_absolute_uri(reverse('shellui-oauth-confirm'))
    switch_account_url = f'{confirm_url}?{urlencode({"action": "switch", "confirm_token": confirm_token})}'
    display_name = user.get_full_name() or user.email or user.get_username()
    methods = _oauth_method_choices_for_company(
        request,
        company,
        redirect_to,
        current_provider=provider,
        client_timezone=client_tz or None,
        client_device_id=client_dev,
    )
    return render(
        request,
        'authapi/oauth_confirm.html',
        {
            'company_name': company.name,
            'display_name': display_name,
            'email': user.email or '',
            'avatar_url': avatar_url or '',
            'initials': _user_display_initials(user, display_name),
            'provider': provider,
            'provider_label': _provider_display_label(provider),
            'confirm_token': confirm_token,
            'confirm_url': confirm_url,
            'switch_account_url': switch_account_url,
            'methods': methods,
            'error_message': error_message,
        },
    )


def _shellui_oauth_bounce_or_json(
    request,
    *,
    message: str,
    status_code: int = status.HTTP_400_BAD_REQUEST,
    error_code: str = 'oauth_authorize_failed',
    redirect_to_raw: str | None = None,
):
    """
    For loopback `redirect_to` targets, redirect back to the Shell app with `shellui_oauth_error`
    query params so the UI can render the message. Otherwise return JSON (e.g. production).
    """
    raw = redirect_to_raw if redirect_to_raw is not None else request.GET.get('redirect_to')
    bounce = loopback_client_bounce_url_for_oauth_error(
        request,
        raw,
        message,
        error_code=error_code,
    )
    if bounce:
        return HttpResponseRedirect(bounce)
    return Response({'error': message, 'error_code': error_code}, status=status_code)


def _join_denied_response(
    *,
    decision,
    redirect_to: str | None = None,
):
    """Return a browser redirect (when possible) or JSON 403 for blocked company joins."""
    code = decision.error_code or 'access_pending'
    message = decision.message or 'Access denied.'
    if redirect_to:
        return HttpResponseRedirect(append_oauth_error_params(redirect_to, message, code))
    return Response({'error': message, 'error_code': code}, status=status.HTTP_403_FORBIDDEN)


def _authenticate_bearer_user(request):
    user = getattr(request, 'user', None)
    if user is not None and user.is_authenticated:
        return user
    auth = ShellUIJWTAuthentication()
    try:
        result = auth.authenticate(request)
    except (InvalidToken, TokenError):
        return None
    if not result:
        return None
    user, _ = result
    return user


def _jwt_bearer_company_id(request) -> int | None:
    """`company_id` from validated JWT access token, or None if missing/invalid."""
    request_auth_token = getattr(request, 'auth', None)
    token_company_id = (
        request_auth_token.get('company_id')
        if request_auth_token is not None and hasattr(request_auth_token, 'get')
        else None
    )
    if token_company_id is None:
        auth = ShellUIJWTAuthentication()
        try:
            authenticated = auth.authenticate(request)
        except (InvalidToken, TokenError):
            return None
        if authenticated:
            _user, token = authenticated
            token_company_id = token.get('company_id') if hasattr(token, 'get') else None
    if token_company_id is None:
        return None
    try:
        return int(token_company_id)
    except (TypeError, ValueError):
        return None


def _required_company_from_request(request, user: User | None = None) -> tuple[Company | None, Response | None]:
    raw = (request.GET.get('company_id') or request.data.get('company_id') or '').strip()
    token_company_id = _jwt_bearer_company_id(request)

    company_id: int | None = None
    if raw:
        try:
            company_id = int(raw)
        except (TypeError, ValueError):
            return None, Response({'error': 'Invalid company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)
    elif token_company_id is not None:
        company_id = token_company_id
    else:
        return None, Response({'error': 'Missing company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)

    if raw and token_company_id is not None and token_company_id != company_id:
        return None, Response(
            {'error': 'Requested company_id does not match token company_id.'},
            status=status.HTTP_403_FORBIDDEN,
        )

    try:
        company = Company.objects.get(pk=company_id)
    except Company.DoesNotExist:
        return None, Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)

    if user is not None:
        if not company.members.filter(pk=user.pk).exists():
            return None, Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)
    return company, None


def _token_claim_int(token, key: str) -> int | None:
    if token is None or not hasattr(token, 'get'):
        return None
    raw = token.get(key)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _required_company_for_token_refresh(
    request,
    *,
    refresh,
    user: User,
) -> tuple[Company | None, Response | None]:
    """Resolve company for refresh grant from body/query, refresh JWT, or optional access JWT."""
    raw = (request.GET.get('company_id') or request.data.get('company_id') or '').strip()
    refresh_company_id = _token_claim_int(refresh, 'company_id')
    access_company_id = _jwt_bearer_company_id(request)

    company_id: int | None = None
    if raw:
        try:
            company_id = int(raw)
        except (TypeError, ValueError):
            return None, Response({'error': 'Invalid company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)
        if refresh_company_id is not None and company_id != refresh_company_id:
            return None, Response(
                {'error': 'Requested company_id does not match refresh token company_id.'},
                status=status.HTTP_403_FORBIDDEN,
            )
        if access_company_id is not None and company_id != access_company_id:
            return None, Response(
                {'error': 'Requested company_id does not match token company_id.'},
                status=status.HTTP_403_FORBIDDEN,
            )
    elif refresh_company_id is not None:
        company_id = refresh_company_id
    elif access_company_id is not None:
        company_id = access_company_id
    else:
        return None, Response({'error': 'Missing company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        company = Company.objects.get(pk=company_id)
    except Company.DoesNotExist:
        return None, Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)

    if not company.members.filter(pk=user.pk).exists():
        return None, Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)
    return company, None


def _require_staff(request):
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    if not user.is_staff:
        return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    return user, company, None


def _require_staff_or_company_owner(request):
    """
    Like `_require_staff` but also allows users in `company.owners` (same `company_id` as token).
    Used for company-scoped admin APIs so operators without Django `is_staff` can use the admin SPA.
    """
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    if user.is_staff or _is_user_company_owner(user, company):
        return user, company, None
    return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)


def _company_from_bearer_token_only(request, user: User) -> tuple[Company | None, Response | None]:
    """Resolve company from JWT/PAT ``company_id`` only (no ``company_id`` query override)."""
    if (request.GET.get('company_id') or '').strip():
        return None, Response(
            {
                'error': 'Remove company_id from the query string; company scope comes from the access token only.',
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    token_company_id = _jwt_bearer_company_id(request)
    if token_company_id is None:
        return None, Response(
            {'error': 'Missing company_id in access token.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        company = Company.objects.get(pk=token_company_id)
    except Company.DoesNotExist:
        return None, Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)
    if not company.members.filter(pk=user.pk).exists():
        return None, Response({'error': 'Forbidden for this company.'}, status=status.HTTP_403_FORBIDDEN)
    return company, None


def _require_staff_or_company_owner_metrics(request):
    """Like `_require_staff_or_company_owner` but company scope is taken only from the Bearer token."""
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    company, cerr = _company_from_bearer_token_only(request, user=user)
    if cerr:
        return None, None, cerr
    if user.is_staff or _is_user_company_owner(user, company):
        return user, company, None
    return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)


def _require_authenticated_company_member(request):
    """Current user must belong to the company implied by JWT ``company_id`` (or explicit ``company_id``)."""
    user = _authenticate_bearer_user(request)
    if not user:
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    company, cerr = _required_company_from_request(request, user=user)
    if cerr:
        return None, None, cerr
    return user, company, None


def _personal_access_token_row(t: PersonalAccessToken, *, include_access_token: str | None = None) -> dict:
    row = {
        'id': str(t.id),
        'user_id': t.user_id,
        'read_only': t.read_only,
        'access_global_metrics': t.access_global_metrics,
        'name': t.name or '',
        'created_at': t.created_at,
        'last_used_at': t.last_used_at,
        'revoked_at': t.revoked_at,
    }
    if include_access_token:
        row['access_token'] = include_access_token
    return row


def _login_event_payload(event: LoginEvent) -> dict:
    return {
        'id': event.id,
        'company_id': event.company_id,
        'created_at': event.created_at,
        'user_id': event.user_id,
        'user_email': event.user.email if event.user_id else None,
        'outcome': event.outcome,
        'provider': event.provider,
        'failure_reason': event.failure_reason or '',
        'is_staff_at_event': event.is_staff_at_event,
        'ip_hash': event.ip_hash or '',
        'user_agent': event.user_agent or '',
        'client_timezone': event.client_timezone or '',
        'client_device_id_hash': event.client_device_id_hash or '',
        'client_country': event.client_country or '',
        'client_city': event.client_city or '',
    }


def _admin_user_payload(user: User, company: Company) -> dict:
    cache_key = f"shellui:user_metadata:{user.id}"
    user_metadata = cache.get(cache_key) or {
        'name': user.get_full_name() or user.get_username(),
        'full_name': user.get_full_name() or user.get_username(),
        'avatar_url': None,
        'is_staff': bool(user.is_staff),
    }
    user_metadata['is_staff'] = bool(user.is_staff)
    user_metadata['is_company_owner'] = _is_user_company_owner(user, company)
    user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
    group_rows = _admin_user_group_rows(user, company)
    user_metadata['groups'] = [row['name'] for row in group_rows]
    user_metadata['last_seen_at'] = _last_seen_at_for_user(user)
    _enrich_user_metadata_avatar(user, user_metadata)
    # `is_active` here means company membership access for this tenant (not User.is_active).
    return {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name or '',
        'last_name': user.last_name or '',
        'is_staff': user.is_staff,
        'is_company_owner': _is_user_company_owner(user, company),
        'is_active': is_company_access_enabled(company, user),
        'groups': group_rows,
        'user_metadata': user_metadata,
    }


@extend_schema_view(
    get=extend_schema(
        tags=['auth-social'],
        summary='Get social provider authorize URL',
        description='Generate an OAuth2 authorize URL for GitHub, Google, or Microsoft.',
        auth=[],
        responses={200: OpenApiResponse(description='Authorization URL generated')},
    )
)
class SocialAuthorizeView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, provider: str):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        company_oauth_client_id = _parse_company_oauth_client_id(request.GET.get('company_oauth_client_id'))
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return Response({'error': oauth_client_err}, status=status.HTTP_400_BAD_REQUEST)
        serializer = ProviderAuthorizeSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        authorize_url = build_authorize_url(
            provider=provider,
            redirect_uri=serializer.validated_data['redirect_uri'],
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
        )
        return Response({'provider': provider, 'authorize_url': authorize_url})


@extend_schema_view(
    post=extend_schema(
        tags=['auth-social'],
        summary='Login with social provider',
        description='Exchange OAuth code and return JWT tokens plus user profile.',
        auth=[],
        request=ProviderCallbackSerializer,
        responses={200: OpenApiResponse(description='Authenticated successfully')},
    )
)
class SocialLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, provider: str):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        company_oauth_client_id = _parse_company_oauth_client_id(
            request.data.get('company_oauth_client_id') or request.GET.get('company_oauth_client_id')
        )
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return Response({'error': oauth_client_err}, status=status.HTTP_400_BAD_REQUEST)
        serializer = ProviderCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        client_tz = serializer.validated_data.get('client_timezone') or ''
        client_dev = serializer.validated_data.get('client_device_id') or None
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=serializer.validated_data['code'],
                redirect_uri=serializer.validated_data['redirect_uri'],
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            userinfo = fetch_provider_userinfo(
                provider,
                access_token,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
                company=company,
                failure_reason=str(exc),
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return Response(
                {'detail': str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])
        join = apply_company_join(company, user, email=email)
        _link_social_account(user=user, provider=provider, provider_id=provider_id, userinfo=userinfo)

        cache.set(
            f"shellui:user_metadata:{user.id}",
            {
                'name': user.get_full_name() or user.get_username(),
                'full_name': user.get_full_name() or user.get_username(),
                'avatar_url': avatar_url,
            },
            timeout=60 * 60 * 24 * 30,
        )

        if not join.allowed:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=user,
                company=company,
                failure_reason=join.error_code or 'access_denied',
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return _join_denied_response(decision=join)

        _notify_user_logged_in_for_oauth(request, user)
        auth_metrics.record_successful_login(provider, company_id=company.id)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            company=company,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        token_payload = _issue_tokens(user, company=company)
        return Response(token_payload, status=status.HTTP_200_OK)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-session'],
        summary='Get Shellui auth capabilities',
        description=(
            'Return authentication capabilities for the Shellui client, including enabled OAuth '
            'providers and feature flags used by the login UI.'
        ),
        auth=[],
        parameters=[
            OpenApiParameter(
                name='company_id',
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Company id used to resolve enabled OAuth clients/settings. Optional when JWT includes company_id.',
            ),
        ],
        responses={
            200: OpenApiResponse(
                description='Capabilities payload with methods, oauthProviders, and feature flags',
            ),
        },
    ),
)
class ShellUIAuthSettingsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        clients = _company_oauth_clients(company)
        providers = sorted({str(row.social_app.provider).lower() for row in clients})
        external = {provider: True for provider in providers}
        oauth_clients = [
            {
                'id': row.id,
                'provider': row.social_app.provider,
                'label': row.social_app.name,
            }
            for row in clients
        ]
        return Response(
            {
                'methods': ['oauth'] if providers else [],
                'oauthProviders': providers,
                'oauthClients': oauth_clients,
                'enable_oauth': bool(providers),
                'enable_magic_link': False,
                'external': external,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth-social'],
        summary='Start OAuth authorization redirect',
        description=(
            'Validate the selected provider and redirect the browser to the provider authorization page. '
            'Use this endpoint for browser-based login.'
        ),
        auth=[],
        parameters=[
            OpenApiParameter(
                name='provider',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    'OAuth provider slug (github, google, or microsoft). '
                    'When omitted, shows a sign-in method picker for the company.'
                ),
            ),
            OpenApiParameter(
                name='redirect_to',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Frontend callback URL. Defaults to /login/callback on current host.',
            ),
            OpenApiParameter(
                name='client_timezone',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    'Optional IANA timezone from the browser (e.g. Europe/Paris), e.g. from '
                    'Intl.DateTimeFormat().resolvedOptions().timeZone. Stored as a coarse hint only.'
                ),
            ),
            OpenApiParameter(
                name='client_device_id',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    'Optional first-party device id (e.g. UUID in localStorage). Sent only as hashed value.'
                ),
            ),
        ],
        responses={
            200: OpenApiResponse(description='Sign-in method picker HTML (when provider is omitted)'),
            302: OpenApiResponse(description='Redirect to provider authorize URL'),
            400: OpenApiResponse(description='Missing redirect_to or provider not enabled'),
            500: OpenApiResponse(description='Provider is enabled but missing OAuth credentials'),
        },
    ),
)
class ShellUIAuthorizeView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            msg = 'Invalid request.'
            data = getattr(company_err, 'data', None)
            if isinstance(data, dict):
                msg = str(data.get('error') or msg)
            bounced = _shellui_oauth_bounce_or_json(
                request,
                message=msg,
                status_code=getattr(company_err, 'status_code', status.HTTP_400_BAD_REQUEST)
                or status.HTTP_400_BAD_REQUEST,
                error_code='authorize_company',
            )
            if isinstance(bounced, HttpResponseRedirect):
                return bounced
            return company_err
        provider = request.GET.get('provider', '').strip().lower()
        company_oauth_client_id = _parse_company_oauth_client_id(request.GET.get('company_oauth_client_id'))
        client_tz = request.GET.get('client_timezone', '')
        client_dev = request.GET.get('client_device_id', '') or None
        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=request.GET.get('redirect_to'),
        )
        if rerr or not redirect_to:
            err_code = (
                'redirect_not_allowed'
                if rerr and ('not allowed' in rerr or 'Invalid redirect_to' in rerr)
                else 'invalid_redirect'
            )
            return _shellui_oauth_bounce_or_json(
                request,
                message=rerr or 'Invalid redirect.',
                error_code=err_code,
            )
        if not provider:
            if not _enabled_oauth_providers(company):
                return _shellui_oauth_bounce_or_json(
                    request,
                    message='No OAuth providers are configured for this company.',
                    error_code='provider_disabled',
                    redirect_to_raw=redirect_to,
                )
            return _render_oauth_method_select_page(
                request,
                company=company,
                redirect_to=redirect_to,
                client_timezone=client_tz or None,
                client_device_id=client_dev,
            )
        if provider not in _enabled_oauth_providers(company):
            return _shellui_oauth_bounce_or_json(
                request,
                message=f"Provider '{provider}' is not enabled.",
                error_code='provider_disabled',
            )
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return _shellui_oauth_bounce_or_json(
                request,
                message=oauth_client_err,
                error_code='oauth_client_unavailable',
            )
        cfg = get_provider_config(
            provider,
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
        )
        if not str(cfg.client_id).strip() or not str(cfg.client_secret).strip():
            return _shellui_oauth_bounce_or_json(
                request,
                message=(
                    f"Provider '{provider}' is missing OAuth credentials for this company. "
                    'Configure a company OAuth client in Django admin or the Shellui admin API.'
                ),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code='provider_oauth_misconfigured',
            )
        switch_account = str(request.GET.get('switch_account', '')).strip().lower() in ('1', 'true', 'yes')
        state = build_oauth_state(
            provider=provider,
            redirect_to=redirect_to,
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
            client_timezone=client_tz or None,
            client_device_id=client_dev,
        )
        # Provider always returns to this service; bounce target is in signed state.
        authorize_url = build_authorize_url(
            provider=provider,
            redirect_uri=oauth_provider_redirect_uri(request),
            state=state,
            company_id=company.id,
            company_oauth_client_id=company_oauth_client_id,
            switch_account=switch_account,
        )
        return HttpResponseRedirect(authorize_url)


@extend_schema_view(
    get=extend_schema(
        tags=['auth-social'],
        summary='Handle OAuth callback and issue Shellui tokens',
        description=(
            'Consume provider callback (code + signed state), exchange code for provider token, '
            'resolve user profile, and redirect to redirect_to with Shellui tokens in the URL hash.'
        ),
        auth=[],
        parameters=[
            OpenApiParameter(
                name='code',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='Authorization code returned by OAuth provider.',
            ),
            OpenApiParameter(
                name='state',
                type=str,
                location=OpenApiParameter.QUERY,
                required=True,
                description='Signed state issued by /api/v1/authorize.',
            ),
        ],
        responses={
            302: OpenApiResponse(description='Redirect to frontend with auth payload in URL fragment'),
            400: OpenApiResponse(description='Missing/invalid callback parameters or provider exchange failure'),
        },
    ),
)
class ShellUIOAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        code = request.GET.get('code', '').strip()
        state_payload, state_err = parse_oauth_state(request.GET.get('state'))
        if state_err or not state_payload:
            return _shellui_oauth_bounce_or_json(
                request,
                message=state_err or 'Invalid OAuth state.',
                error_code='invalid_oauth_state',
                redirect_to_raw=None,
            )
        provider = state_payload['provider']
        redirect_to_raw = state_payload['redirect_to']
        company_oauth_client_id = state_payload.get('company_oauth_client_id')
        client_tz = state_payload.get('client_timezone') or ''
        client_dev = state_payload.get('client_device_id') or None

        try:
            company = Company.objects.get(pk=int(state_payload['company_id']))
        except (Company.DoesNotExist, TypeError, ValueError):
            return _shellui_oauth_bounce_or_json(
                request,
                message='Company not found.',
                error_code='callback_company',
                redirect_to_raw=redirect_to_raw,
            )

        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=redirect_to_raw,
        )
        if rerr or not redirect_to:
            err_code = (
                'redirect_not_allowed'
                if rerr and ('not allowed' in rerr or 'Invalid redirect_to' in rerr)
                else 'invalid_redirect'
            )
            return _shellui_oauth_bounce_or_json(
                request,
                message=rerr or 'Invalid redirect.',
                error_code=err_code,
                redirect_to_raw=redirect_to_raw,
            )
        if not code:
            return _shellui_oauth_bounce_or_json(
                request,
                message='Missing authorization code.',
                error_code='missing_code',
                redirect_to_raw=redirect_to,
            )
        if provider not in _enabled_oauth_providers(company):
            return _shellui_oauth_bounce_or_json(
                request,
                message=f"Provider '{provider}' is not enabled.",
                error_code='provider_disabled',
                redirect_to_raw=redirect_to,
            )
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return _shellui_oauth_bounce_or_json(
                request,
                message=oauth_client_err,
                error_code='oauth_client_unavailable',
                redirect_to_raw=redirect_to,
            )
        callback_url = oauth_provider_redirect_uri(request)
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=code,
                redirect_uri=callback_url,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            userinfo = fetch_provider_userinfo(
                provider,
                access_token,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
                company=company,
                failure_reason=str(exc),
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            bounced = _shellui_oauth_bounce_or_json(
                request,
                message=str(exc),
                error_code='token_exchange_failed',
                redirect_to_raw=redirect_to,
            )
            if isinstance(bounced, HttpResponseRedirect):
                return bounced
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])
        join = apply_company_join(company, user, email=email)
        _link_social_account(user=user, provider=provider, provider_id=provider_id, userinfo=userinfo)

        cache.set(
            f"shellui:user_metadata:{user.id}",
            {
                'name': user.get_full_name() or user.get_username(),
                'full_name': user.get_full_name() or user.get_username(),
                'avatar_url': avatar_url,
            },
            timeout=60 * 60 * 24 * 30,
        )
        if not join.allowed:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=user,
                company=company,
                failure_reason=join.error_code or 'access_denied',
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return _join_denied_response(decision=join, redirect_to=redirect_to)
        return _render_oauth_confirm_page(
            request,
            user=user,
            company=company,
            provider=provider,
            redirect_to=redirect_to,
            avatar_url=avatar_url,
            company_oauth_client_id=company_oauth_client_id,
            client_tz=client_tz,
            client_dev=client_dev,
        )


@method_decorator(csrf_protect, name='dispatch')
class ShellUIOAuthConfirmView(APIView):
    """Browser confirmation step after provider OAuth, before JWT fragment redirect."""

    permission_classes = [AllowAny]

    def get(self, request):
        if str(request.GET.get('action', '')).strip().lower() != 'switch':
            return Response({'error': 'Invalid action.'}, status=status.HTTP_400_BAD_REQUEST)
        payload, err = parse_oauth_confirm_token(request.GET.get('confirm_token'))
        if err or not payload:
            return Response({'error': err or 'Invalid confirmation.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            company = Company.objects.get(pk=int(payload['company_id']))
        except Company.DoesNotExist:
            return Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)
        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=payload['redirect_to'],
        )
        if rerr or not redirect_to:
            return Response({'error': rerr or 'Invalid redirect.'}, status=status.HTTP_400_BAD_REQUEST)
        provider = payload['provider']
        company_oauth_client_id = payload.get('company_oauth_client_id')
        if provider not in _enabled_oauth_providers(company):
            return Response({'error': 'Provider not enabled.'}, status=status.HTTP_400_BAD_REQUEST)
        authorize_params = {
            'provider': provider,
            'company_id': str(company.id),
            'redirect_to': redirect_to,
            'switch_account': '1',
        }
        if company_oauth_client_id:
            authorize_params['company_oauth_client_id'] = str(company_oauth_client_id)
        client_tz = payload.get('client_timezone')
        if client_tz:
            authorize_params['client_timezone'] = client_tz
        client_dev = payload.get('client_device_id')
        if client_dev:
            authorize_params['client_device_id'] = client_dev
        authorize_path = f"{reverse('shellui-authorize')}?{urlencode(authorize_params)}"
        return HttpResponseRedirect(request.build_absolute_uri(authorize_path))
    def post(self, request):
        payload, err = parse_oauth_confirm_token(request.POST.get('confirm_token'))
        if err or not payload:
            return Response({'error': err or 'Invalid confirmation.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(pk=int(payload['user_id']))
            company = Company.objects.get(pk=int(payload['company_id']))
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Company.DoesNotExist:
            return Response({'error': 'Company not found.'}, status=status.HTTP_404_NOT_FOUND)

        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=payload['redirect_to'],
        )
        if rerr or not redirect_to:
            return _render_oauth_confirm_page(
                request,
                user=user,
                company=company,
                provider=payload['provider'],
                redirect_to=payload['redirect_to'],
                avatar_url=payload.get('avatar_url'),
                company_oauth_client_id=payload.get('company_oauth_client_id'),
                client_tz=payload.get('client_timezone') or '',
                client_dev=payload.get('client_device_id'),
                error_message=rerr or 'Invalid redirect.',
            )

        provider = payload['provider']
        if not is_company_access_enabled(company, user):
            return _join_denied_response(
                decision=JoinDecision(
                    allowed=False,
                    error_code='access_denied',
                    message='Access denied for this company.',
                ),
                redirect_to=redirect_to,
            )

        return _finalize_shellui_oauth_login(
            request,
            user=user,
            company=company,
            provider=provider,
            redirect_to=redirect_to,
            avatar_url=payload.get('avatar_url'),
            client_tz=payload.get('client_timezone') or '',
            client_dev=payload.get('client_device_id'),
        )


@extend_schema_view(
    post=extend_schema(
        tags=['auth-social'],
        summary='Exchange OAuth code for Shellui tokens',
        description=(
            'Deprecated for new shells: prefer identity /api/v1/oauth/callback fragment bounce. '
            'Still used by older SPA callbacks that receive provider ?code= directly. '
            'Exchanges provider authorization code and returns Shellui tokens as JSON.'
        ),
        auth=[],
        request=ShellUIOAuthExchangeSerializer,
        responses={
            200: OpenApiResponse(description='Token payload returned'),
            400: OpenApiResponse(description='Invalid payload or provider exchange failure'),
        },
    ),
)
class ShellUIOAuthExchangeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        company, company_err = _required_company_from_request(request)
        if company_err:
            return company_err
        serializer = ShellUIOAuthExchangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        provider = str(validated['provider']).strip().lower()
        code = str(validated['code']).strip()
        redirect_uri = validated['redirect_uri']
        company_oauth_client_id = validated.get('company_oauth_client_id')
        _row, oauth_client_err = _get_company_oauth_client(company, provider, company_oauth_client_id)
        if oauth_client_err:
            return Response({'error': oauth_client_err}, status=status.HTTP_400_BAD_REQUEST)
        client_tz = validated.get('client_timezone') or ''
        client_dev = validated.get('client_device_id') or None
        try:
            access_token = exchange_code_for_token(
                provider=provider,
                code=code,
                redirect_uri=redirect_uri,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            userinfo = fetch_provider_userinfo(
                provider,
                access_token,
                company_id=company.id,
                company_oauth_client_id=company_oauth_client_id,
            )
            provider_id, email, full_name, avatar_url = _extract_user_data(provider, userinfo, access_token)
        except Exception as exc:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=None,
                company=company,
                failure_reason=str(exc),
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': f'{provider}_{provider_id}',
                'first_name': full_name.split(' ')[0],
                'last_name': ' '.join(full_name.split(' ')[1:]),
            },
        )
        if not created:
            if not user.first_name and full_name:
                user.first_name = full_name.split(' ')[0]
            if not user.last_name and ' ' in full_name:
                user.last_name = ' '.join(full_name.split(' ')[1:])
            user.save(update_fields=['first_name', 'last_name'])
        join = apply_company_join(company, user, email=email)
        _link_social_account(user=user, provider=provider, provider_id=provider_id, userinfo=userinfo)

        cache.set(
            f"shellui:user_metadata:{user.id}",
            {
                'name': user.get_full_name() or user.get_username(),
                'full_name': user.get_full_name() or user.get_username(),
                'avatar_url': avatar_url,
            },
            timeout=60 * 60 * 24 * 30,
        )
        if not join.allowed:
            record_login_event(
                request=request,
                outcome=LoginEvent.OUTCOME_FAILURE,
                provider=provider,
                user=user,
                company=company,
                failure_reason=join.error_code or 'access_denied',
                client_timezone=client_tz,
                client_device_id=client_dev,
            )
            return _join_denied_response(decision=join)
        _notify_user_logged_in_for_oauth(request, user)
        payload = _issue_shellui_tokens(user, company=company, avatar_url=avatar_url, oauth_provider=provider)
        auth_metrics.record_successful_login(provider, company_id=company.id)
        record_login_event(
            request=request,
            outcome=LoginEvent.OUTCOME_SUCCESS,
            provider=provider,
            user=user,
            company=company,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return Response(payload, status=status.HTTP_200_OK)


@extend_schema_view(
    post=extend_schema(
        tags=['auth-session'],
        summary='Refresh access token using refresh token',
        description=(
            'Issue a new Shellui token pair from a valid refresh token. '
            'Send `refresh_token` in the JSON body. Bearer access token is optional; '
            'when omitted, `company_id` is taken from the refresh token.'
        ),
        parameters=[
            OpenApiParameter(
                name='grant_type',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Must be refresh_token.',
            ),
        ],
        request=ShellUIRefreshTokenSerializer,
        responses={
            200: OpenApiResponse(description='New access_token and refresh_token payload'),
            400: OpenApiResponse(description='Unsupported grant_type or missing refresh_token'),
            401: OpenApiResponse(description='Invalid refresh token'),
        },
    ),
)
class ShellUITokenView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        logger.info(
            'token refresh request origin=%s referer=%s ua=%s',
            request.headers.get('Origin') or '-',
            request.headers.get('Referer') or '-',
            (request.headers.get('User-Agent') or '-')[:120],
        )
        grant_type = request.GET.get('grant_type') or request.data.get('grant_type')
        if grant_type != 'refresh_token':
            return Response(
                {'error': 'Only grant_type=refresh_token is supported.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        refresh_token = request.data.get('refresh_token')
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            return Response({'error': 'Missing refresh_token.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh = ShellUIRefreshToken(refresh_token)
            user_id = refresh.get('user_id')
            user = User.objects.get(pk=user_id)
        except Exception:
            return Response({'error': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)

        actor = _authenticate_bearer_user(request)
        if actor is not None and int(actor.pk) != int(user.pk):
            return Response(
                {'error': 'Refresh token does not belong to authenticated user.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        company, company_err = _required_company_for_token_refresh(request, refresh=refresh, user=user)
        if company_err:
            return company_err

        if not is_company_access_enabled(company, user):
            return Response(
                {
                    'error': 'Company access is disabled. Contact an administrator.',
                    'error_code': 'access_pending',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        prior_meta = refresh.get('user_metadata')
        prior_avatar = None
        if isinstance(prior_meta, dict):
            prior_avatar = _normalize_avatar_url(prior_meta.get('avatar_url'))

        prior_app = refresh.get('app_metadata')
        touch_user_last_seen(user)

        payload = _issue_shellui_tokens(
            user,
            company=company,
            avatar_url=prior_avatar,
            prior_app_metadata=prior_app if isinstance(prior_app, dict) else None,
        )
        return Response(payload)


@extend_schema_view(
    post=extend_schema(
        tags=['auth-session'],
        summary='Logout current session',
        description=(
            'Shellui-compatible logout endpoint. Requires a valid Bearer access token; '
            '`company_id` may be omitted when the JWT includes `company_id`.'
        ),
        responses={
            200: OpenApiResponse(description='Logout acknowledged'),
            401: OpenApiResponse(description='Missing or invalid Bearer token'),
        },
    ),
)
class ShellUILogoutView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request):
        _company, company_err = _required_company_from_request(request, user=request.user)
        if company_err:
            return company_err
        return Response({'success': True})


@extend_schema_view(
    get=extend_schema(
        tags=['auth-profile'],
        summary='Get current user profile and metadata',
        description=(
            'Return authenticated user identity plus app_metadata/user_metadata. '
            'Requires bearer access token.'
        ),
        responses={
            200: OpenApiResponse(description='Shellui user payload with metadata and preferences'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
    put=extend_schema(
        tags=['auth-profile'],
        summary='Update current user metadata',
        description=(
            'Merge metadata from request.data into cached user_metadata. '
            'If shelluiPreferences are present, they are validated and persisted to UserPreference.'
        ),
        responses={
            200: OpenApiResponse(description='Updated user payload with merged metadata'),
            400: OpenApiResponse(description='Request body must include object field `data`'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
)
class ShellUIUserView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err
        user = User.objects.select_related('activity').get(pk=user.pk)
        cache_key = f"shellui:user_metadata:{user.id}"
        user_metadata = cache.get(cache_key) or {
            'name': user.get_full_name() or user.get_username(),
            'full_name': user.get_full_name() or user.get_username(),
            'avatar_url': None,
            'is_staff': bool(user.is_staff),
        }
        user_metadata['is_staff'] = bool(user.is_staff)
        user_metadata['is_company_owner'] = _is_user_company_owner(user, company)
        user_metadata['shelluiPreferences'] = _user_preferences_payload(user)
        user_metadata['groups'] = _user_group_names(user, company)
        user_metadata['last_seen_at'] = _last_seen_at_for_user(user)
        _enrich_user_metadata_avatar(user, user_metadata)
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django', 'company_id': company.id},
                'user_metadata': user_metadata,
            }
        )

    def put(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err
        user = User.objects.select_related('activity').get(pk=user.pk)
        data = request.data.get('data')
        if not isinstance(data, dict):
            return Response(
                {'error': 'Expected JSON body with object field `data`.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        data = {k: v for k, v in data.items() if k not in _SHELLUI_JWT_PRIVILEGED_METADATA_KEYS}
        cache_key = f"shellui:user_metadata:{user.id}"
        current = cache.get(cache_key) or {}
        merged = {**current, **data}
        incoming_preferences = merged.get('shelluiPreferences')
        if isinstance(incoming_preferences, dict):
            serializer = UserPreferenceSerializer(data=incoming_preferences)
            if serializer.is_valid():
                preference, _ = UserPreference.objects.get_or_create(user=user)
                validated = serializer.validated_data
                if 'themeName' in validated:
                    preference.theme_name = validated['themeName']
                if 'language' in validated:
                    preference.language = validated['language']
                if 'region' in validated:
                    preference.region = validated['region']
                if 'colorScheme' in validated:
                    preference.color_scheme = validated['colorScheme']
                preference.save()
                merged['shelluiPreferences'] = _user_preferences_payload(user)
        else:
            merged['shelluiPreferences'] = _user_preferences_payload(user)
        merged['groups'] = _user_group_names(user, company)
        merged.pop('last_seen_at', None)
        merged['last_seen_at'] = _last_seen_at_for_user(user)
        merged['is_staff'] = bool(user.is_staff)
        merged['is_company_owner'] = _is_user_company_owner(user, company)
        _enrich_user_metadata_avatar(user, merged)
        cache.set(cache_key, merged, timeout=60 * 60 * 24 * 30)
        return Response(
            {
                'id': str(user.id),
                'email': user.email,
                'app_metadata': {'provider': 'django', 'company_id': company.id},
                'user_metadata': merged,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['auth-preferences'],
        summary='Get current user preferences',
        description='Return persisted Shellui preferences for the authenticated user.',
        responses={
            200: OpenApiResponse(description='Current preferences payload'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
    put=extend_schema(
        tags=['auth-preferences'],
        summary='Upsert current user preferences',
        description='Validate and persist partial or full preference payload for authenticated user.',
        request=UserPreferenceSerializer,
        responses={
            200: OpenApiResponse(description='Updated preferences payload'),
            400: OpenApiResponse(description='Invalid preference payload'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
    delete=extend_schema(
        tags=['auth-preferences'],
        summary='Delete current user preferences',
        description='Delete persisted preferences for the authenticated user.',
        responses={
            204: OpenApiResponse(description='Preferences deleted'),
            401: OpenApiResponse(description='Missing or invalid bearer token'),
        },
    ),
)
class ShellUIPreferenceView(APIView):
    permission_classes = [ShellUIPermission]

    def get(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        _company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err

        return Response(_user_preferences_payload(user), status=status.HTTP_200_OK)

    def put(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        _company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err

        serializer = UserPreferenceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        preference, _ = UserPreference.objects.get_or_create(user=user)
        validated = serializer.validated_data
        if 'themeName' in validated:
            preference.theme_name = validated['themeName']
        if 'language' in validated:
            preference.language = validated['language']
        if 'region' in validated:
            preference.region = validated['region']
        if 'colorScheme' in validated:
            preference.color_scheme = validated['colorScheme']
        preference.save()
        return Response(_user_preferences_payload(user), status=status.HTTP_200_OK)

    def delete(self, request):
        user = _authenticate_bearer_user(request)
        if not user:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        _company, company_err = _required_company_from_request(request, user=user)
        if company_err:
            return company_err

        UserPreference.objects.filter(user=user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['directory-users'],
        summary='List users (staff or company owner)',
        description='Paginated directory of users. Requires staff JWT or company-owner membership.',
        operation_id='api_v1_users_list',
        parameters=[
            OpenApiParameter(
                name='q',
                type=str,
                location=OpenApiParameter.QUERY,
                description='Search email, username, name, or numeric id.',
            ),
            OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
        ],
    ),
)
class ShellUIAdminUserListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err

        raw_q = request.GET.get('q', '') or ''
        q = raw_q.strip()
        try:
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(100, max(1, int(request.GET.get('page_size') or 20)))
        except (TypeError, ValueError):
            return Response(
                {'error': 'Invalid page or page_size.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = (
            User.objects.filter(companies=company).distinct().order_by('-id').select_related('activity').prefetch_related('groups')
        )
        if q:
            q_filter = (
                Q(email__icontains=q)
                | Q(username__icontains=q)
                | Q(first_name__icontains=q)
                | Q(last_name__icontains=q)
            )
            if q.isdigit():
                q_filter |= Q(pk=int(q))
            qs = qs.filter(q_filter)

        total = qs.count()
        start = (page - 1) * page_size
        results = [_admin_user_payload(u, company) for u in qs[start : start + page_size]]
        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': results,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['directory-users'],
        summary='Retrieve user (staff or company owner)',
        description='Single user with Shellui metadata. Requires staff JWT or company-owner membership.',
        operation_id='api_v1_users_retrieve',
    ),
    put=extend_schema(
        tags=['directory-users'],
        summary='Update user (staff or company owner)',
        description=(
            'Update Django user fields and/or merge `data` into cached user_metadata (same shape as '
            'PUT /api/v1/user). Staff may change is_staff. Staff and company owners may change '
            'is_active (enables/disables access for this company only), first_name, last_name, '
            'group_ids (within this company), and `data`. Enabling a previously disabled membership '
            'emails the user.'
        ),
        request=ShellUIAdminUserUpdateSerializer,
    ),
)
class ShellUIAdminUserDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            target = User.objects.select_related('activity').get(pk=pk, companies=company)
        except User.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_admin_user_payload(target, company))

    def put(self, request, pk):
        actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            target = User.objects.select_related('activity').get(pk=pk, companies=company)
        except User.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ShellUIAdminUserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        if not actor.is_staff and 'is_staff' in validated:
            return Response(
                {'error': 'Only staff may change is_staff.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if target.pk == actor.pk:
            if validated.get('is_staff') is False:
                return Response(
                    {'error': 'You cannot remove your own staff status.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if validated.get('is_active') is False:
                return Response(
                    {'error': 'You cannot disable your own company access.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        was_company_enabled = is_company_access_enabled(company, target)
        update_fields: list[str] = []
        if 'first_name' in validated:
            target.first_name = validated['first_name']
            update_fields.append('first_name')
        if 'last_name' in validated:
            target.last_name = validated['last_name']
            update_fields.append('last_name')
        if 'is_staff' in validated:
            target.is_staff = validated['is_staff']
            update_fields.append('is_staff')
        if update_fields:
            target.save(update_fields=list(dict.fromkeys(update_fields)))

        if 'is_active' in validated:
            set_company_access(company, target, enabled=bool(validated['is_active']))
            if (not was_company_enabled) and bool(validated['is_active']):
                notify_user_access_enabled(company, target)

        if 'group_ids' in validated:
            requested_ids = set(validated['group_ids'])
            company_groups = CompanyGroup.objects.filter(company=company).order_by('id')
            existing_ids = set(company_groups.values_list('id', flat=True))
            missing_ids = sorted(requested_ids - existing_ids)
            if missing_ids:
                return Response(
                    {'error': f'Unknown group ids for this company: {missing_ids}.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            for g in company_groups:
                if g.id in requested_ids:
                    g.members.add(target)
                else:
                    g.members.remove(target)

        data = validated.get('data')
        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k not in _SHELLUI_JWT_PRIVILEGED_METADATA_KEYS}
            cache_key = f"shellui:user_metadata:{target.id}"
            current = cache.get(cache_key) or {}
            merged = {**current, **data}
            merged.pop('last_seen_at', None)
            merged['is_staff'] = bool(target.is_staff)
            merged['is_company_owner'] = _is_user_company_owner(target, company)
            cache.set(cache_key, merged, timeout=60 * 60 * 24 * 30)
            incoming_preferences = merged.get('shelluiPreferences')
            if isinstance(incoming_preferences, dict):
                pref_serializer = UserPreferenceSerializer(data=incoming_preferences)
                if pref_serializer.is_valid():
                    preference, _ = UserPreference.objects.get_or_create(user=target)
                    pvalidated = pref_serializer.validated_data
                    if 'themeName' in pvalidated:
                        preference.theme_name = pvalidated['themeName']
                    if 'language' in pvalidated:
                        preference.language = pvalidated['language']
                    if 'region' in pvalidated:
                        preference.region = pvalidated['region']
                    if 'colorScheme' in pvalidated:
                        preference.color_scheme = pvalidated['colorScheme']
                    preference.save()
                    merged['shelluiPreferences'] = _user_preferences_payload(target)
            else:
                merged['shelluiPreferences'] = _user_preferences_payload(target)

        return Response(_admin_user_payload(target, company))


@extend_schema_view(
    get=extend_schema(
        tags=['directory-groups'],
        summary='List auth groups (staff or company owner)',
        description='All company groups for requested company with `user_count`.',
        operation_id='api_v1_groups_list',
    ),
    post=extend_schema(
        tags=['directory-groups'],
        summary='Create auth group (staff or company owner)',
        description='Create a named group.',
        request=ShellUIAdminGroupCreateSerializer,
    ),
)
class ShellUIAdminGroupListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        rows = list(
            CompanyGroup.objects.filter(company=company)
            .annotate(user_count=Count('members', distinct=True))
            .values('id', 'name', 'user_count')
            .order_by('name')
        )
        return Response(rows)

    def post(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminGroupCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = str(serializer.validated_data['name']).strip()
        if not name:
            return Response({'error': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if CompanyGroup.objects.filter(company=company, name=name).exists():
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        g = CompanyGroup.objects.create(company=company, name=name)
        return Response({'id': g.id, 'name': g.name, 'user_count': 0}, status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['directory-groups'],
        summary='Retrieve auth group (staff or company owner)',
        operation_id='api_v1_groups_retrieve',
    ),
    put=extend_schema(
        tags=['directory-groups'],
        summary='Rename auth group (staff or company owner)',
        request=ShellUIAdminGroupUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['directory-groups'],
        summary='Delete auth group (staff or company owner)',
    ),
)
class ShellUIAdminGroupDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            g = CompanyGroup.objects.filter(company=company).annotate(user_count=Count('members', distinct=True)).get(pk=pk)
        except CompanyGroup.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'id': g.id, 'name': g.name, 'user_count': g.user_count})

    def put(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            g = CompanyGroup.objects.filter(company=company).annotate(user_count=Count('members', distinct=True)).get(pk=pk)
        except CompanyGroup.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ShellUIAdminGroupUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = str(serializer.validated_data['name']).strip()
        if not name:
            return Response({'error': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if CompanyGroup.objects.filter(company=company, name=name).exclude(pk=g.pk).exists():
            return Response(
                {'error': 'A group with this name already exists.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        g.name = name
        g.save(update_fields=['name'])
        g = CompanyGroup.objects.filter(company=company).annotate(user_count=Count('members', distinct=True)).get(pk=g.pk)
        return Response({'id': g.id, 'name': g.name, 'user_count': g.user_count})

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            g = CompanyGroup.objects.filter(company=company).get(pk=pk)
        except CompanyGroup.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        g.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['oauth-clients'],
        summary='List company OAuth clients (staff or company owner)',
        description='All OAuth client keys for the active company, grouped by provider in UI clients.',
        operation_id='api_v1_oauth_clients_list',
    ),
    post=extend_schema(
        tags=['oauth-clients'],
        summary='Create company OAuth client (staff or company owner)',
        request=ShellUIAdminOAuthClientCreateSerializer,
    ),
)
class ShellUIAdminOAuthClientListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        rows = CompanyOAuthClient.objects.filter(company=company).select_related('social_app').order_by(
            'social_app__provider',
            'social_app__name',
            'id',
        )
        return Response([_oauth_client_payload(r) for r in rows])

    def post(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminOAuthClientCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        enabled = set(_supported_oauth_providers())
        try:
            social_app = SocialApp.objects.get(pk=validated['social_app_id'])
        except SocialApp.DoesNotExist:
            return Response({'error': 'SocialApp not found.'}, status=status.HTTP_400_BAD_REQUEST)
        if str(social_app.provider).strip().lower() not in enabled:
            return Response(
                {'error': f"Provider '{social_app.provider}' is not supported."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not str(social_app.client_id).strip() or not str(social_app.secret).strip():
            return Response(
                {'error': 'Selected SocialApp is missing client_id or secret.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            row = CompanyOAuthClient.objects.create(
                company=company,
                social_app=social_app,
                is_active=bool(validated.get('is_active', True)),
            )
        except IntegrityError:
            return Response(
                {'error': 'This SocialApp is already mapped for this company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(_oauth_client_payload(row), status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['oauth-social-apps'],
        summary='List available allauth SocialApps for OAuth setup (staff or company owner)',
        description=(
            'Returns SocialApp rows for supported providers, plus whether each app '
            'is already linked to the active company OAuth mappings.'
        ),
    ),
    post=extend_schema(
        tags=['oauth-social-apps'],
        summary='Create SocialApp OAuth key and optionally map to company',
        request=ShellUIAdminOAuthSocialAppCreateSerializer,
    ),
)
class ShellUIAdminOAuthSocialAppListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        enabled_providers = set(_supported_oauth_providers())
        apps = SocialApp.objects.all().order_by('provider', 'name', 'id')
        rows = [
            _oauth_social_app_payload(company, app)
            for app in apps
            if str(app.provider).strip().lower() in enabled_providers
        ]
        return Response(
            {
                'providers': sorted(enabled_providers),
                'social_apps': rows,
            }
        )

    def post(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminOAuthSocialAppCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        provider = str(validated['provider']).strip().lower()
        if provider not in set(_supported_oauth_providers()):
            return Response(
                {'error': f"Provider '{provider}' is not supported."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if CompanyOAuthClient.objects.filter(company=company, social_app__provider=provider).exists():
            return Response(
                {'error': f"Provider '{provider}' is already configured for this company."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        social_settings = {}
        tenant = str(validated.get('tenant') or '').strip()
        if tenant:
            social_settings = {'tenant': tenant}
        app = SocialApp.objects.create(
            provider=provider,
            name=_generated_social_app_name(provider, company),
            client_id=str(validated['client_id']).strip(),
            secret=str(validated['client_secret']).strip(),
            key='',
            settings=social_settings,
        )
        try:
            current_site = Site.objects.get_current()
            app.sites.add(current_site)
        except Exception:
            pass
        mapping, _created = CompanyOAuthClient.objects.get_or_create(
            company=company,
            social_app=app,
            defaults={'is_active': True},
        )
        return Response(
            {
                'social_app': _oauth_social_app_payload(company, app),
                'mapping': _oauth_client_payload(mapping) if mapping else None,
            },
            status=status.HTTP_201_CREATED,
        )


@extend_schema_view(
    put=extend_schema(
        tags=['oauth-social-apps'],
        summary='Update SocialApp OAuth key for this company',
        request=ShellUIAdminOAuthSocialAppUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['oauth-social-apps'],
        summary='Delete SocialApp OAuth key for this company',
        description=(
            'Deletes the company mapping and the underlying SocialApp. '
            'For safety, deletion is blocked when the SocialApp is mapped to another company.'
        ),
    ),
)
class ShellUIAdminOAuthSocialAppDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def put(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            app = SocialApp.objects.get(pk=pk)
        except SocialApp.DoesNotExist:
            return Response({'error': 'SocialApp not found.'}, status=status.HTTP_404_NOT_FOUND)
        mapping = CompanyOAuthClient.objects.filter(company=company, social_app=app).first()
        if not mapping:
            return Response(
                {'error': 'This SocialApp is not mapped to the current company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = ShellUIAdminOAuthSocialAppUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        if 'client_id' in validated:
            app.client_id = str(validated['client_id']).strip()
        if 'client_secret' in validated:
            app.secret = str(validated['client_secret']).strip()
        settings_data = app.settings if isinstance(app.settings, dict) else {}
        settings_data = dict(settings_data)
        if 'tenant' in validated:
            tenant = str(validated['tenant']).strip()
            if tenant:
                settings_data['tenant'] = tenant
            else:
                settings_data.pop('tenant', None)
        app.settings = settings_data
        app.save()
        app.refresh_from_db()
        return Response(_oauth_social_app_payload(company, app))

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            app = SocialApp.objects.get(pk=pk)
        except SocialApp.DoesNotExist:
            return Response({'error': 'SocialApp not found.'}, status=status.HTTP_404_NOT_FOUND)
        mapping = CompanyOAuthClient.objects.filter(company=company, social_app=app).first()
        if not mapping:
            return Response(
                {'error': 'This SocialApp is not mapped to the current company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        has_other_company_mappings = CompanyOAuthClient.objects.filter(social_app=app).exclude(company=company).exists()
        if has_other_company_mappings:
            return Response(
                {'error': 'Cannot delete this key because it is mapped to another company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        app.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['oauth-clients'],
        summary='Retrieve company OAuth client (staff or company owner)',
        operation_id='api_v1_oauth_clients_retrieve',
    ),
    put=extend_schema(
        tags=['oauth-clients'],
        summary='Update company OAuth client (staff or company owner)',
        request=ShellUIAdminOAuthClientUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['oauth-clients'],
        summary='Delete company OAuth client (staff or company owner)',
    ),
)
class ShellUIAdminOAuthClientDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthClient.objects.get(pk=pk, company=company)
        except CompanyOAuthClient.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_oauth_client_payload(row))

    def put(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthClient.objects.get(pk=pk, company=company)
        except CompanyOAuthClient.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ShellUIAdminOAuthClientUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        if 'social_app_id' in validated:
            enabled = set(_supported_oauth_providers())
            try:
                social_app = SocialApp.objects.get(pk=validated['social_app_id'])
            except SocialApp.DoesNotExist:
                return Response({'error': 'SocialApp not found.'}, status=status.HTTP_400_BAD_REQUEST)
            if str(social_app.provider).strip().lower() not in enabled:
                return Response(
                    {'error': f"Provider '{social_app.provider}' is not supported."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not str(social_app.client_id).strip() or not str(social_app.secret).strip():
                return Response(
                    {'error': 'Selected SocialApp is missing client_id or secret.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            row.social_app = social_app
        if 'is_active' in validated:
            row.is_active = validated['is_active']
        try:
            row.save()
        except IntegrityError:
            return Response(
                {'error': 'This SocialApp is already mapped for this company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        row.refresh_from_db()
        return Response(_oauth_client_payload(row))

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthClient.objects.get(pk=pk, company=company)
        except CompanyOAuthClient.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        row.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


def _oauth_redirect_payload(row: CompanyOAuthRedirect) -> dict:
    return {
        'id': row.id,
        'base_url': row.base_url,
        'label': row.label or '',
        'is_active': bool(row.is_active),
        'created_at': row.created_at.isoformat() if row.created_at else None,
    }


@extend_schema_view(
    get=extend_schema(
        tags=['oauth-redirects'],
        summary='List company OAuth redirect allowlist (staff or company owner)',
        description=(
            'Origins allowed as post-OAuth bounce targets (`redirect_to`). '
            'Loopback (localhost / 127.0.0.1 / ::1) is always allowed without a row. '
            'Empty allowlist denies non-loopback redirects.'
        ),
        operation_id='api_v1_oauth_redirects_list',
    ),
    post=extend_schema(
        tags=['oauth-redirects'],
        summary='Add OAuth redirect allowlist origin (staff or company owner)',
        request=ShellUIAdminOAuthRedirectCreateSerializer,
    ),
)
class ShellUIAdminOAuthRedirectListView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        rows = CompanyOAuthRedirect.objects.filter(company=company).order_by('id')
        return Response([_oauth_redirect_payload(r) for r in rows])

    def post(self, request):
        from apps.companies.redirect_allowlist import normalize_allowlist_origin

        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        serializer = ShellUIAdminOAuthRedirectCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        origin, nerr = normalize_allowlist_origin(validated['base_url'])
        if nerr or not origin:
            return Response({'error': nerr or 'Invalid base_url.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            row = CompanyOAuthRedirect.objects.create(
                company=company,
                base_url=origin,
                label=str(validated.get('label') or '').strip()[:150],
                is_active=bool(validated.get('is_active', True)),
            )
        except IntegrityError:
            return Response(
                {'error': 'This origin is already on the allowlist for this company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(_oauth_redirect_payload(row), status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        tags=['oauth-redirects'],
        summary='Retrieve OAuth redirect allowlist entry (staff or company owner)',
        operation_id='api_v1_oauth_redirects_retrieve',
    ),
    patch=extend_schema(
        tags=['oauth-redirects'],
        summary='Update OAuth redirect allowlist entry (staff or company owner)',
        request=ShellUIAdminOAuthRedirectUpdateSerializer,
    ),
    delete=extend_schema(
        tags=['oauth-redirects'],
        summary='Delete OAuth redirect allowlist entry (staff or company owner)',
    ),
)
class ShellUIAdminOAuthRedirectDetailView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthRedirect.objects.get(pk=pk, company=company)
        except CompanyOAuthRedirect.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_oauth_redirect_payload(row))

    def patch(self, request, pk):
        from apps.companies.redirect_allowlist import normalize_allowlist_origin

        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthRedirect.objects.get(pk=pk, company=company)
        except CompanyOAuthRedirect.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ShellUIAdminOAuthRedirectUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        if 'base_url' in validated:
            origin, nerr = normalize_allowlist_origin(validated['base_url'])
            if nerr or not origin:
                return Response({'error': nerr or 'Invalid base_url.'}, status=status.HTTP_400_BAD_REQUEST)
            row.base_url = origin
        if 'label' in validated:
            row.label = str(validated.get('label') or '').strip()[:150]
        if 'is_active' in validated:
            row.is_active = bool(validated['is_active'])
        try:
            row.save()
        except IntegrityError:
            return Response(
                {'error': 'This origin is already on the allowlist for this company.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        row.refresh_from_db()
        return Response(_oauth_redirect_payload(row))

    def delete(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            row = CompanyOAuthRedirect.objects.get(pk=pk, company=company)
        except CompanyOAuthRedirect.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        row.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='List login audit events (staff or company owner)',
        description=(
            'Paginated OAuth sign-in attempts (success and failure). '
            'Contains privacy-oriented fields (hashed IP, truncated user-agent). '
        ),
        operation_id='api_v1_login_events_list',
        parameters=[
            OpenApiParameter(
                name='user_id',
                type=int,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Filter by Django user id.',
            ),
            OpenApiParameter(
                name='outcome',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='success or failure.',
            ),
            OpenApiParameter(
                name='provider',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='OAuth provider slug (github, google, microsoft).',
            ),
            OpenApiParameter(
                name='is_staff_at_event',
                type=bool,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Filter rows where the user was staff at login time.',
            ),
            OpenApiParameter(
                name='created_after',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='ISO 8601 datetime (inclusive lower bound).',
            ),
            OpenApiParameter(
                name='created_before',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='ISO 8601 datetime (exclusive upper bound).',
            ),
            OpenApiParameter(
                name='client_country',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring match on GeoIP country (stored value).',
            ),
            OpenApiParameter(
                name='client_city',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring match on GeoIP city.',
            ),
            OpenApiParameter(
                name='client_timezone',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description='Case-insensitive substring match on client IANA timezone.',
            ),
            OpenApiParameter(
                name='language',
                type=str,
                location=OpenApiParameter.QUERY,
                required=False,
                description=(
                    "Filter rows where the user's saved Shellui preference language matches "
                    '(e.g. en, fr). Omits anonymous events (no user).'
                ),
            ),
            OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, required=False),
            OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, required=False),
        ],
        responses={200: OpenApiResponse(description='Paginated list of login audit events')},
    ),
)
class ShellUIAdminLoginEventListView(APIView):
    permission_classes = [ShellUIPermission]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err

        try:
            page = max(1, int(request.GET.get('page') or 1))
            page_size = min(100, max(1, int(request.GET.get('page_size') or 20)))
        except (TypeError, ValueError):
            return Response(
                {'error': 'Invalid page or page_size.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = LoginEvent.objects.filter(company=company).select_related('user').order_by('-created_at', '-id')

        uid = request.GET.get('user_id')
        if uid is not None and str(uid).strip():
            try:
                qs = qs.filter(user_id=int(uid))
            except (TypeError, ValueError):
                return Response({'error': 'Invalid user_id.'}, status=status.HTTP_400_BAD_REQUEST)

        outcome = (request.GET.get('outcome') or '').strip().lower()
        if outcome:
            if outcome not in (LoginEvent.OUTCOME_SUCCESS, LoginEvent.OUTCOME_FAILURE):
                return Response({'error': 'Invalid outcome.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(outcome=outcome)

        prov = (request.GET.get('provider') or '').strip().lower()
        if prov:
            qs = qs.filter(provider=prov)

        staff_raw = request.GET.get('is_staff_at_event')
        if staff_raw is not None and str(staff_raw).strip() != '':
            s = str(staff_raw).strip().lower()
            if s in ('1', 'true', 'yes'):
                qs = qs.filter(is_staff_at_event=True)
            elif s in ('0', 'false', 'no'):
                qs = qs.filter(is_staff_at_event=False)
            else:
                return Response(
                    {'error': 'Invalid is_staff_at_event (use true or false).'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        ca = (request.GET.get('created_after') or '').strip()
        if ca:
            dt = parse_datetime(ca)
            if not dt:
                return Response({'error': 'Invalid created_after.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(created_at__gte=dt)

        cb = (request.GET.get('created_before') or '').strip()
        if cb:
            dt = parse_datetime(cb)
            if not dt:
                return Response({'error': 'Invalid created_before.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(created_at__lt=dt)

        cc = (request.GET.get('client_country') or '').strip()
        if cc:
            qs = qs.filter(client_country__icontains=cc)

        city = (request.GET.get('client_city') or '').strip()
        if city:
            qs = qs.filter(client_city__icontains=city)

        ctz = (request.GET.get('client_timezone') or '').strip()
        if ctz:
            qs = qs.filter(client_timezone__icontains=ctz)

        lang = (request.GET.get('language') or '').strip().lower()
        if lang:
            allowed_lang = {choice[0] for choice in UserPreference.LANGUAGE_CHOICES}
            if lang not in allowed_lang:
                return Response({'error': 'Invalid language.'}, status=status.HTTP_400_BAD_REQUEST)
            qs = qs.filter(user__preference__language=lang)

        total = qs.count()
        start = (page - 1) * page_size
        rows = [_login_event_payload(e) for e in qs[start : start + page_size]]
        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'results': rows,
            }
        )


@extend_schema_view(
    get=extend_schema(
        tags=['audit-events'],
        summary='Retrieve login audit event (staff or company owner)',
        description='Single login event row.',
        operation_id='api_v1_login_events_retrieve',
        responses={200: OpenApiResponse(description='Login audit event')},
    ),
)
class ShellUIAdminLoginEventDetailView(APIView):
    permission_classes = [ShellUIPermission]

    def get(self, request, pk):
        _actor, company, err = _require_staff_or_company_owner(request)
        if err:
            return err
        try:
            event = LoginEvent.objects.select_related('user').get(pk=pk, company=company)
        except LoginEvent.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_login_event_payload(event))


@extend_schema_view(
    get=extend_schema(
        tags=['personal-access-tokens'],
        summary='List personal access tokens',
        description='JWT-based personal access tokens for the signed-in user in the current company.',
    ),
    post=extend_schema(
        tags=['personal-access-tokens'],
        summary='Create personal access token',
        request=ShellUIPersonalAccessTokenCreateSerializer,
        description=(
            'Returns a Shellui-shaped JWT once in `access_token`. '
            '`read_only` restricts to safe HTTP methods. Only Django staff may set '
            '`access_global_metrics` for GET /api/v1/metrics/all.'
        ),
    ),
)
class ShellUIPersonalAccessTokenListCreateView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def get(self, request):
        user, company, err = _require_authenticated_company_member(request)
        if err:
            return err
        qs = PersonalAccessToken.objects.filter(company=company, user=user).order_by('-created_at')
        return Response({'results': [_personal_access_token_row(t) for t in qs]})

    def post(self, request):
        user, company, err = _require_authenticated_company_member(request)
        if err:
            return err
        serializer = ShellUIPersonalAccessTokenCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        read_only = bool(serializer.validated_data.get('read_only'))
        access_global_metrics = bool(serializer.validated_data.get('access_global_metrics'))
        if access_global_metrics and not user.is_staff:
            return Response(
                {'error': 'Only staff may create tokens with access to global metrics.'},
                status=status.HTTP_403_FORBIDDEN,
            )
        name = serializer.validated_data.get('name') or ''
        row, access_token_str = _issue_personal_access_token(
            user,
            company,
            read_only=read_only,
            access_global_metrics=access_global_metrics,
            name=name,
        )
        return Response(
            _personal_access_token_row(row, include_access_token=access_token_str),
            status=status.HTTP_201_CREATED,
        )


@extend_schema_view(
    post=extend_schema(
        tags=['personal-access-tokens'],
        summary='Revoke personal access token',
        description='Marks the token as revoked; JWT access stops immediately.',
    ),
)
class ShellUIPersonalAccessTokenRevokeView(APIView):
    permission_classes = [ShellUIPermission]
    serializer_class = ShellUIOpenAPISerializer

    def post(self, request, key_id):
        user, company, err = _require_authenticated_company_member(request)
        if err:
            return err
        try:
            row = PersonalAccessToken.objects.get(pk=key_id, company=company, user=user)
        except PersonalAccessToken.DoesNotExist:
            return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        if row.revoked_at is not None:
            return Response({'error': 'Already revoked.'}, status=status.HTTP_400_BAD_REQUEST)
        row.revoked_at = datetime.now(timezone.utc)
        row.save(update_fields=['revoked_at'])
        return Response(_personal_access_token_row(row))


@extend_schema_view(
    get=extend_schema(
        tags=['platform-metrics'],
        summary='Prometheus metrics (staff or company owner)',
        description=(
            'Prometheus text exposition (openmetrics) for the company in the Bearer token '
            '(JWT or PAT must include a `company_id` claim). Do not send `company_id` as a query parameter.'
        ),
        responses={
            200: OpenApiResponse(description='text/plain Prometheus exposition'),
            400: OpenApiResponse(
                description='Missing company_id in token, or company_id was sent in the query string'
            ),
            401: OpenApiResponse(description='Missing or invalid Bearer token'),
            403: OpenApiResponse(description='Forbidden'),
        },
    ),
)
class ShellUIAdminMetricsView(APIView):
    permission_classes = [ShellUIPermission]
    renderer_classes = [PrometheusTextRenderer]

    def get(self, request):
        _actor, company, err = _require_staff_or_company_owner_metrics(request)
        if err:
            return err
        return HttpResponse(
            auth_metrics.metrics_http_body(company_id=company.id),
            content_type=auth_metrics.METRICS_CONTENT_TYPE,
        )


@extend_schema_view(
    get=extend_schema(
        tags=['platform-metrics'],
        summary='Prometheus metrics for all companies (staff)',
        description=(
            'Global Prometheus text exposition across all companies. Requires a Django staff user '
            'or a PAT created by staff with `access_global_metrics` (claim `pat_agm`).'
        ),
        responses={
            200: OpenApiResponse(description='text/plain Prometheus exposition'),
            401: OpenApiResponse(description='Missing or invalid Bearer token'),
            403: OpenApiResponse(description='Forbidden (not staff and no global-metrics PAT)'),
        },
    ),
)
class ShellUIAdminGlobalMetricsView(APIView):
    permission_classes = [ShellUIPermission]
    renderer_classes = [PrometheusTextRenderer]

    def get(self, request):
        user = getattr(request, 'user', None)
        if user is None or not user.is_authenticated:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        auth = getattr(request, 'auth', None)
        if user.is_staff:
            pass
        elif auth is not None and auth.get('pat_agm') is True:
            pass
        else:
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        return HttpResponse(
            auth_metrics.metrics_http_body(),
            content_type=auth_metrics.METRICS_CONTENT_TYPE,
        )
