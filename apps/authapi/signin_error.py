"""HTML sign-in error pages for a person in the browser.

API clients that send ``Accept: application/json`` still receive JSON.
The page never includes a token, an auth code, or a sign-in URL.
A **Back to the app** link is added only when the request already has a
redirect whose scheme is registered for that company.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from apps.authapi.desktop_return import desktop_return_language
from apps.companies.models import Company
from apps.companies.redirect_allowlist import (
    desktop_error_deep_link,
    is_custom_scheme_redirect,
    normalize_client_redirect_url,
    redirect_url_allowed_for_company,
)

_COPY = {
    'en': {
        'title': "Sign-in didn't finish",
        'go_back': 'Go back',
        'back_to_app': 'Back to the app',
        'noscript': 'Use your browser back control to leave this page.',
        'messages': {
            'invalid_redirect': 'This address cannot be used for sign-in. Start again from the app.',
            'unregistered_scheme': (
                'This app has no registered sign-in scheme. Register a scheme, then start again.'
            ),
            'redirect_not_allowed': (
                'This app cannot receive the sign-in. Check the allowlist, then try again.'
            ),
            'pkce_required': 'The app did not finish the sign-in check. Start again from the app.',
            'invalid_code_challenge_method': (
                'The app sent a sign-in check this service does not accept. Start again from the app.'
            ),
            'invalid_code_challenge': (
                'The app sent a sign-in check this service cannot use. Start again from the app.'
            ),
            'invalid_code_verifier': 'The sign-in check did not match. Start again from the app.',
            'pkce_verification_failed': 'The sign-in check did not match. Start again from the app.',
            'magic_link_expired': 'This sign-in link has expired. Start again from the app.',
            'magic_link_invalid': 'This sign-in link is not valid. Start again from the app.',
            'magic_link_used': 'This sign-in link was already used. Start again from the app.',
            'invalid_oauth_state': 'This sign-in has expired. Start again from the app.',
            'missing_code': 'The sign-in response was incomplete. Start again from the app.',
            'magic_link_disabled': 'Magic link sign-in is off for this company. Use another sign-in method.',
            'default': 'Sign-in did not finish. Go back and start again.',
        },
    },
    'fr': {
        'title': "La connexion n'a pas abouti",
        'go_back': 'Retour',
        'back_to_app': "Revenir à l'application",
        'noscript': 'Utilisez le retour du navigateur pour quitter cette page.',
        'messages': {
            'invalid_redirect': (
                "Cette adresse ne peut pas servir à la connexion. Recommencez depuis l'application."
            ),
            'unregistered_scheme': (
                "Cette application n'a pas de schéma de connexion enregistré. "
                'Enregistrez un schéma, puis recommencez.'
            ),
            'redirect_not_allowed': (
                "Cette application ne peut pas recevoir la connexion. "
                "Vérifiez la liste d'autorisation, puis réessayez."
            ),
            'pkce_required': (
                "L'application n'a pas terminé la vérification de connexion. "
                "Recommencez depuis l'application."
            ),
            'invalid_code_challenge_method': (
                "L'application a envoyé une vérification que ce service n'accepte pas. "
                "Recommencez depuis l'application."
            ),
            'invalid_code_challenge': (
                "L'application a envoyé une vérification incorrecte. "
                "Recommencez depuis l'application."
            ),
            'invalid_code_verifier': (
                "La vérification de connexion ne correspond pas. Recommencez depuis l'application."
            ),
            'pkce_verification_failed': (
                "La vérification de connexion ne correspond pas. Recommencez depuis l'application."
            ),
            'magic_link_expired': (
                "Ce lien de connexion a expiré. Recommencez depuis l'application."
            ),
            'magic_link_invalid': (
                "Ce lien de connexion n'est pas valable. Recommencez depuis l'application."
            ),
            'magic_link_used': (
                "Ce lien de connexion a déjà été utilisé. Recommencez depuis l'application."
            ),
            'invalid_oauth_state': "Cette connexion a expiré. Recommencez depuis l'application.",
            'missing_code': (
                "La réponse de connexion est incomplète. Recommencez depuis l'application."
            ),
            'magic_link_disabled': (
                'La connexion par lien magique est désactivée pour cette entreprise. '
                'Utilisez une autre méthode de connexion.'
            ),
            'default': "La connexion n'a pas abouti. Revenez en arrière et recommencez.",
        },
    },
}


def _accept_q(accept: str, media: str) -> float:
    for part in accept.split(','):
        bits = [bit.strip() for bit in part.split(';') if bit.strip()]
        if not bits or bits[0] != media:
            continue
        quality = 1.0
        for param in bits[1:]:
            if param.startswith('q='):
                try:
                    quality = float(param[2:])
                except ValueError:
                    quality = 0.0
        return quality
    return 0.0


def request_wants_html(request: HttpRequest) -> bool:
    """True when the client prefers an HTML page over JSON.

    Browsers send ``text/html``. API clients send ``application/json`` or no
    HTML type, and those requests keep the JSON body.
    """
    accept = (request.META.get('HTTP_ACCEPT') or '').lower()
    if 'text/html' not in accept:
        return False
    if 'application/json' not in accept:
        return True
    return _accept_q(accept, 'text/html') >= _accept_q(accept, 'application/json')


def safe_desktop_error_url(
    request: HttpRequest,
    company: Company | None,
    redirect_to: str | None,
    error_code: str,
) -> str | None:
    """Deep link with ``error``, or None when the scheme is not registered."""
    if company is None or not (redirect_to or '').strip():
        return None
    normalized, err = normalize_client_redirect_url(request, redirect_to or '')
    if err or not normalized or not is_custom_scheme_redirect(normalized):
        return None
    if not redirect_url_allowed_for_company(company, normalized, request):
        return None
    return desktop_error_deep_link(normalized, error_code)


def signin_error_response(
    request: HttpRequest,
    *,
    message: str,
    error_code: str,
    status_code: int = 400,
    company: Company | None = None,
    redirect_to: str | None = None,
    json_body: dict | None = None,
) -> HttpResponse:
    """JSON for API clients. An HTML page for a browser."""
    if not request_wants_html(request):
        body = json_body if json_body is not None else {'error': message, 'error_code': error_code}
        if json_body is not None:
            return JsonResponse(body, status=status_code)
        # Django views (SAML ACS finish) render this outside an APIView, which
        # only works once a renderer is set. APIView overwrites it afterwards.
        response = Response(body, status=status_code)
        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = 'application/json'
        response.renderer_context = {}
        return response
    lang = desktop_return_language(request)
    copy = _COPY.get(lang) or _COPY['en']
    page_message = copy['messages'].get(error_code) or copy['messages']['default']
    back_to_app_url = safe_desktop_error_url(request, company, redirect_to, error_code)
    return render(
        request,
        'authapi/signin_error.html',
        {
            'page_language': lang,
            'title': copy['title'],
            'message': page_message,
            'go_back': copy['go_back'],
            'back_to_app_label': copy['back_to_app'],
            'back_to_app_url': back_to_app_url or '',
            'noscript': copy['noscript'],
            'error_code': error_code,
        },
        status=status_code,
    )
