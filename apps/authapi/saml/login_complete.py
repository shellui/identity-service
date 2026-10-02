"""Complete Shellui login after a validated SAML assertion."""

from __future__ import annotations

from django.core.cache import cache
from django.http import HttpRequest, HttpResponseRedirect

from apps.actions.user_hooks import emit_oauth_user_created_if_new
from apps.authapi.login_audit import LoginOutcome, record_login_event
from apps.authapi.oauth import should_skip_oauth_confirm
from apps.authapi.oauth_social_account import bind_oauth_social_app, compose_social_account_uid
from apps.authapi.oauth_user import OAuthProfile
from apps.authapi.provider_registry import catalog_entry_for_social_app
from apps.authapi.saml.organization import idp_entity_id_from_settings, shellui_company_id_from_app
from apps.authapi.saml.user_resolution import SAML_EMAIL_CONFLICT, resolve_saml_user
from apps.companies.access import (
    JoinDecision,
    apply_company_join,
    invitation_revoked_decision,
    is_company_access_enabled,
    is_login_blocked_by_revoked_invitation,
)
from apps.companies.models import Company


def profile_from_saml_auth(request: HttpRequest, social_app, auth) -> tuple[OAuthProfile | None, str | None]:
    from allauth.socialaccount.providers.saml.provider import SAMLProvider

    from apps.authapi.oauth_social_account import social_account_provider_key

    bind_oauth_social_app(request, social_app)
    entry = catalog_entry_for_social_app(social_app)
    provider = SAMLProvider(request, app=social_app)
    sociallogin = provider.sociallogin_from_response(request, auth)
    uid = str(sociallogin.account.uid or '').strip()
    if not uid:
        return None, 'saml_profile_invalid'
    name_id = str(auth.get_nameid() or '').strip()
    name_id_format = str(auth.get_nameid_format() or '').strip()
    if (
        name_id_format == 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        and name_id
        and uid == name_id
    ):
        return None, 'saml_nameid_transient'
    email = str(sociallogin.user.email or '').strip().lower()
    if not email or email.endswith('@saml.local'):
        return None, 'saml_email_required'
    full_name = sociallogin.user.get_full_name() or email.split('@')[0]
    composed_uid = compose_social_account_uid(
        entry=entry,
        social_app=social_app,
        raw_uid=uid,
    )
    social_provider = social_account_provider_key(entry=entry, social_app=social_app)
    userinfo = dict(sociallogin.account.extra_data or {})
    userinfo.setdefault('email', email)
    userinfo.setdefault('uid', uid)
    return (
        OAuthProfile(
            provider_id=uid,
            social_provider=social_provider,
            social_uid=composed_uid or uid,
            email=email,
            full_name=full_name,
            avatar_url=None,
            email_verified_for_link=False,
            userinfo=userinfo,
        ),
        None,
    )


def complete_shellui_saml_login(
    request: HttpRequest,
    *,
    social_app,
    auth,
    shellui_state: dict,
) -> HttpResponseRedirect:
    from apps.authapi.views import (
        _finalize_shellui_oauth_login,
        _join_denied_response,
        _link_social_account,
        _render_oauth_confirm_page,
        _shellui_oauth_bounce_or_json,
    )

    company_id = shellui_state.get('company_id')
    try:
        company = Company.objects.get(pk=int(company_id))
    except (Company.DoesNotExist, TypeError, ValueError):
        return _shellui_oauth_bounce_or_json(
            request,
            message='Company not found.',
            error_code='callback_company',
            redirect_to_raw=shellui_state.get('redirect_to'),
        )
    owner = shellui_company_id_from_app(social_app)
    if owner is None or int(owner) != int(company.id):
        return _shellui_oauth_bounce_or_json(
            request,
            message='SAML IdP is not configured for this company.',
            error_code='saml_company_mismatch',
            redirect_to_raw=shellui_state.get('redirect_to'),
        )
    profile, perror = profile_from_saml_auth(request, social_app, auth)
    provider = 'saml'
    client_tz = shellui_state.get('client_timezone') or ''
    client_dev = shellui_state.get('client_device_id') or None
    redirect_to = shellui_state.get('redirect_to') or ''
    if perror or profile is None:
        record_login_event(
            request=request,
            outcome=LoginOutcome.FAILURE,
            provider=provider,
            user=None,
            company=company,
            failure_reason=perror or 'saml_profile_invalid',
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return _shellui_oauth_bounce_or_json(
            request,
            message=perror or 'SAML sign-in failed.',
            error_code=perror or 'saml_identity_failed',
            redirect_to_raw=redirect_to,
        )
    if is_login_blocked_by_revoked_invitation(company, profile.email):
        revoked = invitation_revoked_decision()
        record_login_event(
            request=request,
            outcome=LoginOutcome.FAILURE,
            provider=provider,
            user=None,
            company=company,
            failure_reason=revoked.error_code,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return _join_denied_response(decision=revoked, redirect_to=redirect_to)
    user, created, uerror = resolve_saml_user(
        company=company,
        social_app=social_app,
        profile=profile,
    )
    if uerror or user is None:
        failure_code = uerror or 'saml_user_resolution_failed'
        record_login_event(
            request=request,
            outcome=LoginOutcome.FAILURE,
            provider=provider,
            user=None,
            company=company,
            failure_reason=failure_code,
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        error_code = uerror if uerror in {
            SAML_EMAIL_CONFLICT,
            'saml_nameid_transient',
            'saml_email_required',
        } else 'saml_identity_failed'
        return _shellui_oauth_bounce_or_json(
            request,
            message=failure_code,
            error_code=error_code,
            redirect_to_raw=redirect_to,
        )
    emit_oauth_user_created_if_new(company, user, created=created, oauth_provider=provider)
    join = apply_company_join(company, user, email=profile.email)
    _link_social_account(user=user, profile=profile, userinfo=profile.userinfo)
    cache.set(
        f"shellui:user_metadata:{user.id}",
        {
            'name': user.get_full_name() or user.get_username(),
            'full_name': user.get_full_name() or user.get_username(),
            'avatar_url': profile.avatar_url,
        },
        timeout=60 * 60 * 24 * 30,
    )
    if not join.allowed:
        record_login_event(
            request=request,
            outcome=LoginOutcome.FAILURE,
            provider=provider,
            user=user,
            company=company,
            failure_reason=join.error_code or 'access_denied',
            client_timezone=client_tz,
            client_device_id=client_dev,
        )
        return _join_denied_response(decision=join, redirect_to=redirect_to)
    if should_skip_oauth_confirm(provider, email=profile.email, userinfo=profile.userinfo):
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
            avatar_url=profile.avatar_url,
            client_tz=client_tz,
            client_dev=client_dev,
            token_delivery=shellui_state.get('token_delivery'),
        )
    return _render_oauth_confirm_page(
        request,
        user=user,
        company=company,
        provider=provider,
        redirect_to=redirect_to,
        avatar_url=profile.avatar_url,
        client_tz=client_tz,
        client_dev=client_dev,
        token_delivery=shellui_state.get('token_delivery'),
    )
