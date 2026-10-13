"""Browser page that sends the person back to a desktop app.

Automatic navigation to a custom scheme is blocked by some browsers. The page
always shows a link the person can activate.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation.trans_real import parse_accept_lang_header

from apps.authapi.magic_link import normalize_magic_link_language
from apps.companies.redirect_allowlist import (
    SHELLUI_OAUTH_ERROR_PARAM,
    is_custom_scheme_redirect,
)

_COPY = {
    'en': {
        'success_title': 'Return to the app',
        'success_body': 'Sign-in is complete. If the app did not open, use the button.',
        'error_title': 'Return to the app',
        'error_body': 'Sign-in did not finish. Return to the app to see what happened.',
        'button': 'Return to app',
    },
    'fr': {
        'success_title': "Revenir à l'application",
        'success_body': "La connexion est terminée. Si l'application ne s'est pas ouverte, utilisez le bouton.",
        'error_title': "Revenir à l'application",
        'error_body': "La connexion n'a pas abouti. Revenez à l'application pour voir ce qui s'est passé.",
        'button': "Revenir à l'application",
    },
}


def desktop_return_language(request: HttpRequest | None) -> str:
    header = ''
    if request is not None:
        header = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
    for tag, _quality in parse_accept_lang_header(header):
        lang = normalize_magic_link_language(tag)
        if lang:
            return lang
    return normalize_magic_link_language(getattr(settings, 'MAGIC_LINK_EMAIL_DEFAULT_LANGUAGE', None)) or 'en'


def client_redirect_reports_success(location: str) -> bool:
    """False when the deep link already carries a sign-in error for the app."""
    query = parse_qs(urlsplit(location).query)
    return SHELLUI_OAUTH_ERROR_PARAM not in query


def client_redirect_response(
    request: HttpRequest,
    location: str,
    *,
    succeeded: bool = True,
) -> HttpResponse:
    """302 for an http(s) target. A custom scheme renders the return page."""
    if not is_custom_scheme_redirect(location):
        return HttpResponseRedirect(location)
    lang = desktop_return_language(request)
    copy = _COPY[lang]
    title_key = 'success_title' if succeeded else 'error_title'
    body_key = 'success_body' if succeeded else 'error_body'
    return render(
        request,
        'authapi/desktop_return.html',
        {
            'page_language': lang,
            'title': copy[title_key],
            'body': copy[body_key],
            'button': copy['button'],
            'return_url': location,
            'succeeded': succeeded,
        },
    )
