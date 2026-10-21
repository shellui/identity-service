"""Shellui error pages and JSON errors.

Paths under ``/api/`` always get JSON, whatever the ``Accept`` header says.
Every other path gets a branded HTML page. Neither one includes the
exception, a stack trace, or the requested path.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.template import loader

from apps.authapi.desktop_return import desktop_return_language

API_PREFIX = '/api/'

_JSON = {
    400: ('Bad request.', 'bad_request'),
    403: ('You do not have permission to do this.', 'permission_denied'),
    404: ('Not found.', 'not_found'),
    500: ('Server error.', 'server_error'),
}
_CSRF_JSON = ('CSRF check failed. Reload the page and try again.', 'csrf_failed')

_COPY = {
    'en': {
        'home': 'Back to home',
        400: ("This request didn't work", 'The page got a request it could not read. Go back to home and try again.'),
        403: ("You can't open this page", 'Your account does not have access to this page.'),
        404: ("This page doesn't exist", 'The link may be wrong, or the page has moved.'),
        500: ('Something went wrong', 'The service could not finish your request. Try again in a moment.'),
        'csrf': ('This form has expired', 'Reload the page, then send the form again.'),
    },
    'fr': {
        'home': "Revenir à l'accueil",
        400: (
            "Cette demande n'a pas abouti",
            "La page a reçu une demande illisible. Revenez à l'accueil et réessayez.",
        ),
        403: (
            'Vous ne pouvez pas ouvrir cette page',
            "Votre compte n'a pas accès à cette page.",
        ),
        404: (
            "Cette page n'existe pas",
            'Le lien est peut-être faux, ou la page a été déplacée.',
        ),
        500: (
            "Une erreur s'est produite",
            "Le service n'a pas pu terminer votre demande. Réessayez dans un instant.",
        ),
        'csrf': (
            'Ce formulaire a expiré',
            'Rechargez la page, puis envoyez à nouveau le formulaire.',
        ),
    },
}

_FALLBACK_HTML = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Shellui Identity</title></head>'
    '<body><h1>Something went wrong</h1><p>Try again in a moment.</p><p><a href="/">Back to home</a></p></body></html>'
)


def is_api_path(request: HttpRequest) -> bool:
    return (request.path or '').startswith(API_PREFIX)


def _language(request: HttpRequest) -> str:
    try:
        return desktop_return_language(request)
    except Exception:
        return 'en'


def error_response(request: HttpRequest, status: int, *, csrf: bool = False) -> HttpResponse:
    if is_api_path(request):
        message, code = _CSRF_JSON if csrf else _JSON[status]
        return JsonResponse({'error': message, 'error_code': code}, status=status)
    lang = _language(request)
    copy = _COPY.get(lang) or _COPY['en']
    title, message = copy['csrf' if csrf else status]
    context = {
        'page_language': lang,
        'status_code': status,
        'title': title,
        'message': message,
        'home_label': copy['home'],
    }
    try:
        # No request context: the 500 page must not depend on sessions, users or the database.
        body = loader.render_to_string('errors/error.html', context)
    except Exception:
        body = _FALLBACK_HTML
    return HttpResponse(body, status=status, content_type='text/html; charset=utf-8')


def bad_request(request, exception=None):
    return error_response(request, 400)


def permission_denied(request, exception=None):
    return error_response(request, 403)


def page_not_found(request, exception=None):
    return error_response(request, 404)


def server_error(request):
    return error_response(request, 500)


def csrf_failure(request, reason='', template_name=None):
    return error_response(request, 403, csrf=True)
