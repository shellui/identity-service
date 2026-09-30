"""Identity-hosted SAML SP endpoints (per company IdP / organization slug)."""

from __future__ import annotations

import binascii
import logging
from http import HTTPStatus

from allauth.core.internal import httpkit
from allauth.socialaccount.providers.base.constants import AuthProcess
from allauth.socialaccount.providers.saml.provider import SAMLProvider
from allauth.socialaccount.sessions import LoginSession
from django.contrib.auth import logout as django_auth_logout
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app
from apps.authapi.saml.errors import saml_http_error, saml_json_error
from apps.authapi.saml.login_complete import complete_shellui_saml_login
from apps.authapi.saml.organization import (
    get_saml_app_for_slug,
    idp_entity_id_from_settings,
    shellui_company_id_from_app,
)
from apps.authapi.saml.request_id import stash_saml_request_id
from apps.authapi.saml.security import (
    enforce_replay_protection,
    extract_in_response_to_from_saml_response_b64,
    validate_in_response_to,
)
from apps.authapi.saml.utils import build_auth, build_saml_config
from apps.companies.models import Company
from apps.companies.redirect_allowlist import validate_redirect_to_for_company

logger = logging.getLogger(__name__)

SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY = 'shellui_saml_authn_request_id'


class SAMLViewMixin:
    def get_app(self, organization_slug: str):
        return get_saml_app_for_slug(self.request, organization_slug)

    def get_provider(self, organization_slug: str):
        app = self.get_app(organization_slug)
        bind_oauth_social_app(self.request, app)
        return SAMLProvider(self.request, app=app)


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLACSView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        from django.urls import reverse

        url = reverse('shellui-saml-finish-acs', kwargs={'organization_slug': organization_slug})
        response = HttpResponseRedirect(url)
        acs_session = LoginSession(request, 'saml_acs_session', 'saml-acs-session')
        acs_session.store.update({'request': httpkit.serialize_request(request)})
        acs_session.save(response)
        return response


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLFinishACSView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        social_app = provider.app
        acs_session = LoginSession(request, 'saml_acs_session', 'saml-acs-session')
        acs_request_data = acs_session.store.get('request')
        acs_session.delete()
        if not acs_request_data:
            logger.error('SAML ACS session missing')
            return saml_http_error(error_code='saml_acs_session_missing', status=HTTPStatus.BAD_REQUEST)
        acs_request = httpkit.deserialize_request(acs_request_data, HttpRequest())
        if not acs_request.META.get('HTTP_HOST'):
            acs_request.META['HTTP_HOST'] = request.get_host()
        if not acs_request.META.get('wsgi.url_scheme'):
            acs_request.META['wsgi.url_scheme'] = 'https' if request.is_secure() else 'http'
        acs_request.session = request.session
        bind_oauth_social_app(acs_request, social_app)

        saml_response_b64 = acs_request.POST.get('SAMLResponse')
        in_response_to = extract_in_response_to_from_saml_response_b64(saml_response_b64)
        if in_response_to:
            pending = request.session.pop(SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY, None)
            if not pending or str(pending) != str(in_response_to):
                logger.error('SAML InResponseTo session binding failed')
                return saml_http_error(error_code='saml_in_response_to_session_mismatch', status=HTTPStatus.BAD_REQUEST)

        with oauth_allauth_request(acs_request, social_app=social_app):
            auth = build_auth(acs_request, social_app)
        errors: list[str] = []
        error_reason = None
        try:
            auth.process_response(request_id=in_response_to)
        except binascii.Error:
            errors = ['invalid_response']
            error_reason = 'invalid_response'
        except OneLogin_Saml2_Error as exc:
            errors = ['error']
            error_reason = str(exc)
        if not errors:
            errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason() or error_reason
            logger.error('SAML ACS errors: %s (%s)', ','.join(errors), error_reason)
            return saml_http_error(error_code='saml_response_invalid', status=HTTPStatus.BAD_REQUEST)
        if not auth.is_authenticated():
            return saml_http_error(error_code='saml_auth_cancelled', status=HTTPStatus.BAD_REQUEST)

        company_id = shellui_company_id_from_app(social_app)
        if company_id is None:
            return saml_http_error(error_code='saml_company_mismatch', status=HTTPStatus.FORBIDDEN)
        idp_entity = idp_entity_id_from_settings(
            social_app.settings if isinstance(social_app.settings, dict) else {}
        )
        if not enforce_replay_protection(auth, company_id=company_id, idp_entity_id=idp_entity):
            return saml_http_error(error_code='saml_assertion_replay', status=HTTPStatus.BAD_REQUEST)

        shellui_state = None
        if in_response_to:
            shellui_state = validate_in_response_to(
                in_response_to=in_response_to,
                expected_company_id=company_id,
            )
        else:
            settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
            advanced = settings_data.get('advanced') if isinstance(settings_data.get('advanced'), dict) else {}
            if advanced.get('reject_idp_initiated_sso', True):
                logger.error('IdP-initiated SAML rejected')
                return saml_http_error(error_code='saml_idp_initiated_rejected', status=HTTPStatus.BAD_REQUEST)
            shellui_state = {'company_id': company_id, 'redirect_to': '/', 'token_delivery': 'code'}

        if not isinstance(shellui_state, dict):
            return saml_http_error(error_code='saml_in_response_to_invalid', status=HTTPStatus.BAD_REQUEST)

        bind_oauth_social_app(request, social_app)
        return complete_shellui_saml_login(
            request,
            social_app=social_app,
            auth=auth,
            shellui_state=shellui_state,
        )


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLMetadataView(SAMLViewMixin, View):
    def get(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        social_app = self.get_app(organization_slug)
        settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
        try:
            config = build_saml_config(request, settings_data, organization_slug)
        except ValueError:
            return saml_json_error(error_code='saml_metadata_invalid', status=500)
        saml_settings = OneLogin_Saml2_Settings(settings=config, sp_validation_only=True)
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        if errors:
            return saml_json_error(error_code='saml_metadata_invalid', status=500)
        return HttpResponse(content=metadata, content_type='text/xml')


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLLoginView(SAMLViewMixin, View):
    def get(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        from apps.authapi.views import _resolve_token_delivery

        provider = self.get_provider(organization_slug)
        social_app = provider.app
        company_id = shellui_company_id_from_app(social_app)
        if company_id is None:
            return saml_json_error(error_code='saml_company_mismatch', status=HTTPStatus.FORBIDDEN)
        try:
            company = Company.objects.get(pk=int(company_id))
        except (Company.DoesNotExist, TypeError, ValueError):
            return saml_json_error(error_code='callback_company', status=HTTPStatus.BAD_REQUEST)

        redirect_to, rerr = validate_redirect_to_for_company(
            company=company,
            request=request,
            redirect_to_raw=request.GET.get('redirect_to'),
        )
        if rerr or not redirect_to:
            return saml_json_error(error_code='redirect_not_allowed', status=HTTPStatus.BAD_REQUEST)

        token_delivery = _resolve_token_delivery(request=request)
        shellui_payload = {
            'company_id': int(company.id),
            'redirect_to': redirect_to,
            'client_timezone': request.GET.get('client_timezone') or '',
            'client_device_id': request.GET.get('client_device_id') or '',
            'token_delivery': token_delivery,
            'company_oauth_client_id': request.GET.get('company_oauth_client_id'),
        }
        bind_oauth_social_app(request, social_app)
        with oauth_allauth_request(request, social_app=social_app):
            auth = build_auth(request, social_app)
            redirect_url = auth.login(return_to='')
            request_id = auth.get_last_request_id()
        if not request_id:
            return saml_json_error(error_code='saml_authn_request_failed', status=HTTPStatus.BAD_REQUEST)
        request.session[SHELLUI_SAML_AUTHN_REQUEST_SESSION_KEY] = str(request_id)
        request.session.modified = True
        stash_saml_request_id(request_id=request_id, payload=shellui_payload)
        provider.stash_redirect_state(
            request,
            AuthProcess.LOGIN,
            next_url=None,
            data=None,
            state_id=request_id,
            shellui=shellui_payload,
        )
        return HttpResponseRedirect(redirect_url)


def _validate_saml_slo_relay_state(request: HttpRequest, *, company: Company) -> str | None:
    relay = str(request.GET.get('RelayState') or request.POST.get('RelayState') or '').strip()
    if not relay:
        return None
    redirect_to, rerr = validate_redirect_to_for_company(
        company=company,
        request=request,
        redirect_to_raw=relay,
    )
    if rerr or not redirect_to:
        return None
    return redirect_to


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLSLSView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        social_app = provider.app
        company_id = shellui_company_id_from_app(social_app)
        if company_id is None:
            return saml_http_error(error_code='saml_company_mismatch', status=HTTPStatus.FORBIDDEN)
        try:
            company = Company.objects.get(pk=int(company_id))
        except (Company.DoesNotExist, TypeError, ValueError):
            return saml_http_error(error_code='callback_company', status=HTTPStatus.BAD_REQUEST)

        bind_oauth_social_app(request, social_app)
        auth = build_auth(request, social_app, require_signed_messages=True)

        def _end_session() -> None:
            django_auth_logout(request)

        try:
            redirect_to = auth.process_slo(delete_session_cb=_end_session, keep_local_session=False)
        except OneLogin_Saml2_Error:
            return saml_http_error(error_code='saml_sls_failed', status=HTTPStatus.BAD_REQUEST)
        errors = auth.get_errors()
        if errors:
            return saml_http_error(error_code='saml_sls_failed', status=HTTPStatus.BAD_REQUEST)
        relay = _validate_saml_slo_relay_state(request, company=company)
        if redirect_to is None and relay:
            redirect_to = relay
        if not redirect_to:
            redirect_to = '/'
        elif relay and redirect_to != relay:
            safe_relay = _validate_saml_slo_relay_state(request, company=company)
            if safe_relay:
                redirect_to = safe_relay
            else:
                return saml_http_error(error_code='redirect_not_allowed', status=HTTPStatus.BAD_REQUEST)
        return HttpResponseRedirect(redirect_to)
