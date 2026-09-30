"""Identity-hosted SAML SP endpoints (per company IdP / organization slug)."""

from __future__ import annotations

import binascii
import logging
from http import HTTPStatus

from allauth.core.internal import httpkit
from allauth.socialaccount.providers.base.constants import AuthError, AuthProcess
from allauth.socialaccount.providers.saml.provider import SAMLProvider
from allauth.socialaccount.sessions import LoginSession
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from apps.authapi.oauth_request_context import oauth_allauth_request
from apps.authapi.oauth_social_account import bind_oauth_social_app
from apps.authapi.saml.login_complete import complete_shellui_saml_login
from apps.authapi.saml.organization import (
    get_saml_app_for_slug,
    idp_entity_id_from_settings,
    shellui_company_id_from_app,
)
from apps.authapi.saml.request_id import stash_saml_request_id
from apps.authapi.saml.security import enforce_replay_protection, validate_in_response_to
from apps.authapi.saml.utils import build_auth, build_saml_config

logger = logging.getLogger(__name__)


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
        acs_request = None
        acs_request_data = acs_session.store.get('request')
        if acs_request_data:
            acs_request = httpkit.deserialize_request(acs_request_data, HttpRequest())
        acs_session.delete()
        if not acs_request:
            logger.error('SAML ACS session missing')
            return HttpResponse('saml_acs_session_missing', status=HTTPStatus.BAD_REQUEST, content_type='text/plain')
        if not acs_request.META.get('HTTP_HOST'):
            acs_request.META['HTTP_HOST'] = request.get_host()
        if not acs_request.META.get('wsgi.url_scheme'):
            acs_request.META['wsgi.url_scheme'] = 'https' if request.is_secure() else 'http'
        acs_request.session = request.session
        bind_oauth_social_app(acs_request, social_app)
        with oauth_allauth_request(acs_request, social_app=social_app):
            auth = build_auth(acs_request, social_app)
        errors: list[str] = []
        error_reason = None
        try:
            auth.process_response(request_id=None)
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
            return HttpResponse(
                'saml_response_invalid',
                status=HTTPStatus.BAD_REQUEST,
                content_type='text/plain',
            )
        if not auth.is_authenticated():
            return HttpResponse('saml_auth_cancelled', status=HTTPStatus.BAD_REQUEST, content_type='text/plain')

        company_id = shellui_company_id_from_app(social_app)
        if company_id is None:
            return HttpResponse('saml_company_mismatch', status=HTTPStatus.FORBIDDEN, content_type='text/plain')
        idp_entity = idp_entity_id_from_settings(
            social_app.settings if isinstance(social_app.settings, dict) else {}
        )
        if not enforce_replay_protection(auth, company_id=company_id, idp_entity_id=idp_entity):
            return HttpResponse('saml_assertion_replay', status=HTTPStatus.BAD_REQUEST, content_type='text/plain')

        in_response_to = auth.get_last_response_in_response_to()
        shellui_state = None
        if in_response_to:
            shellui_state = validate_in_response_to(
                in_response_to=in_response_to,
                expected_company_id=company_id,
            )
            if shellui_state is None:
                login_state = provider.unstash_redirect_state(acs_request, in_response_to)
                if isinstance(login_state, dict):
                    shellui_state = login_state.get('shellui')
        else:
            settings_data = social_app.settings if isinstance(social_app.settings, dict) else {}
            advanced = settings_data.get('advanced') if isinstance(settings_data.get('advanced'), dict) else {}
            if advanced.get('reject_idp_initiated_sso', True):
                logger.error('IdP-initiated SAML rejected')
                return HttpResponse(
                    'saml_idp_initiated_rejected',
                    status=HTTPStatus.BAD_REQUEST,
                    content_type='text/plain',
                )
            shellui_state = {'company_id': company_id, 'redirect_to': '/', 'token_delivery': 'code'}

        if not isinstance(shellui_state, dict):
            return HttpResponse('saml_in_response_to_invalid', status=HTTPStatus.BAD_REQUEST, content_type='text/plain')

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
        config = build_saml_config(request, settings_data, organization_slug)
        saml_settings = OneLogin_Saml2_Settings(settings=config, sp_validation_only=True)
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        if errors:
            return JsonResponse({'error_code': 'saml_metadata_invalid', 'errors': errors}, status=500)
        return HttpResponse(content=metadata, content_type='text/xml')


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLLoginView(SAMLViewMixin, View):
    def get(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        social_app = provider.app
        company_id = shellui_company_id_from_app(social_app)
        shellui_payload = {
            'company_id': request.GET.get('company_id') or company_id,
            'redirect_to': request.GET.get('redirect_to') or '',
            'client_timezone': request.GET.get('client_timezone') or '',
            'client_device_id': request.GET.get('client_device_id') or '',
            'token_delivery': request.GET.get('token_delivery') or 'code',
            'company_oauth_client_id': request.GET.get('company_oauth_client_id'),
        }
        bind_oauth_social_app(request, social_app)
        with oauth_allauth_request(request, social_app=social_app):
            auth = build_auth(request, social_app)
            redirect_url = auth.login(return_to='')
            request_id = auth.get_last_request_id()
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


@method_decorator(csrf_exempt, name='dispatch')
class ShellUISAMLSLSView(SAMLViewMixin, View):
    def get(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        auth = build_auth(request, provider.app)
        try:
            redirect_to = auth.process_slo(delete_session_cb=lambda: None, keep_local_session=True)
        except OneLogin_Saml2_Error as exc:
            return HttpResponse(str(exc), status=HTTPStatus.BAD_REQUEST, content_type='text/plain')
        errors = auth.get_errors()
        if errors:
            return HttpResponse(
                auth.get_last_error_reason() or 'saml_sls_failed',
                status=HTTPStatus.BAD_REQUEST,
                content_type='text/plain',
            )
        if not redirect_to:
            redirect_to = '/'
        return HttpResponseRedirect(redirect_to)

    def post(self, request: HttpRequest, organization_slug: str) -> HttpResponse:
        return self.get(request, organization_slug)
