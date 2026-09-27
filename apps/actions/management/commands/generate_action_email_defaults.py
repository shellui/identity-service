"""Generate React Email editor JSON defaults (maintainer utility).

Only JSON ships on disk. The admin compiles HTML from these documents and stores it
on each email rule; the send path substitutes placeholders into that stored HTML.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.actions.registry import all_event_types

# Primary CTA is a real TipTap `button` node (not a bare link mark) so the editor
# theme applies padding/background.
#
# Copy uses a tiny inline markup — NEVER raw HTML in TipTap text nodes:
#   **{{ data.email }}**  → bold mark in JSON


_BOLD_RE = re.compile(r'\*\*(.+?)\*\*')


def _text_node(text: str, *, bold: bool = False) -> dict:
    node: dict = {'type': 'text', 'text': text}
    if bold:
        node['marks'] = [{'type': 'bold'}]
    return node


def _inline_nodes_from_markup(text: str) -> list[dict]:
    """Split ``**bold**`` segments into TipTap text nodes (no HTML tags)."""
    nodes: list[dict] = []
    pos = 0
    for match in _BOLD_RE.finditer(text):
        if match.start() > pos:
            nodes.append(_text_node(text[pos : match.start()]))
        nodes.append(_text_node(match.group(1), bold=True))
        pos = match.end()
    if pos < len(text):
        nodes.append(_text_node(text[pos:]))
    if not nodes:
        nodes.append(_text_node(text))
    return nodes


def _paragraph_from_markup(text: str) -> dict:
    return {'type': 'paragraph', 'content': _inline_nodes_from_markup(text)}


def _heading(level: int, text: str) -> dict:
    return {'type': 'heading', 'attrs': {'level': level}, 'content': [_text_node(text)]}


def _button(label: str, href: str) -> dict:
    """TipTap / @react-email/editor Button node — theme supplies bg + padding."""
    return {
        'type': 'button',
        'attrs': {
            'href': href,
            'class': 'button',
            'alignment': 'center',
        },
        'content': [_text_node(label)],
    }


def _link_paragraph(label: str, href: str) -> dict:
    """Fallback URL line: plain TipTap link mark (not HTML)."""
    return {
        'type': 'paragraph',
        'content': [
            _text_node(f'{label} '),
            {
                'type': 'text',
                'text': href,
                'marks': [{'type': 'link', 'attrs': {'href': href, 'target': '_blank'}}],
            },
        ],
    }


def _document(
    *,
    kicker: str,
    heading: str,
    paragraphs: list[str],
    cta: tuple[str, str] | None = None,
    link_fallback: tuple[str, str] | None = None,
    footer: str | None = None,
) -> dict:
    doc_content: list[dict] = [
        _paragraph_from_markup(kicker),
        _heading(1, heading),
    ]
    for para in paragraphs:
        doc_content.append(_paragraph_from_markup(para))
    if cta:
        doc_content.append(_button(cta[0], cta[1]))
    if link_fallback:
        doc_content.append(_link_paragraph(link_fallback[0], link_fallback[1]))
    if footer:
        doc_content.append(_paragraph_from_markup(footer))

    # Editor auto-wraps top-level blocks in a container; seed one so defaults
    # match what getJSON() returns after open.
    return {
        'type': 'doc',
        'content': [
            {
                'type': 'container',
                'content': doc_content,
            }
        ],
    }


def _event_copy(event_id: str, lang: str) -> dict:
    company = '{{ envelope.company.name }}'
    en = lang == 'en'
    copies: dict[str, dict[str, dict]] = {
        'identity.scim.user.provisioned': {
            'en': {
                'heading': f'You have access to {company}',
                'paragraphs': [
                    f'Your organization enabled your access. Sign in with **{{{{ data.email }}}}** when your app is ready.',
                    'If you already had an account elsewhere in Shellui, use the same email address.',
                ],
                'footer': "Questions? Contact your organization's administrator.",
            },
            'fr': {
                'heading': f'Vous avez accès à {company}',
                'paragraphs': [
                    f'Votre organisation a activé votre accès. Connectez-vous avec **{{{{ data.email }}}}** lorsque votre application est prête.',
                    'Si vous aviez déjà un compte ailleurs dans Shellui, utilisez la même adresse e-mail.',
                ],
                'footer': "Des questions ? Contactez l'administrateur de votre organisation.",
            },
        },
        'identity.scim.user.deprovisioned': {
            'en': {
                'heading': f'Your access to {company} has ended',
                'paragraphs': [
                    f'You no longer have access to this organization (**{{{{ data.email }}}}**). Your Shellui account was not deleted and may still work for other organizations.',
                    "If this looks wrong, contact your organization's administrator.",
                ],
            },
            'fr': {
                'heading': f'Votre accès à {company} est terminé',
                'paragraphs': [
                    f'Vous n\'avez plus accès à cette organisation (**{{{{ data.email }}}}**). Votre compte Shellui n\'a pas été supprimé et peut encore fonctionner pour d\'autres organisations.',
                    "Si cela vous semble incorrect, contactez l'administrateur de votre organisation.",
                ],
            },
        },
        'identity.user.created': {
            'en': {
                'heading': f'Welcome to {company}',
                'paragraphs': [
                    f'An account for **{{{{ data.email }}}}** is ready. Sign in when your administrator shares the link to your app.',
                    'You can continue with {{ data.oauth_provider }} on the sign-in page when OAuth is enabled.',
                ],
                'footer': "If you did not expect this message, contact your organization's administrator.",
            },
            'fr': {
                'heading': f'Bienvenue chez {company}',
                'paragraphs': [
                    f'Un compte pour **{{{{ data.email }}}}** est prêt. Connectez-vous lorsque votre administrateur partage le lien vers votre application.',
                    'Vous pouvez continuer avec {{ data.oauth_provider }} sur la page de connexion lorsque OAuth est activé.',
                ],
                'footer': "Si vous n'attendiez pas ce message, contactez l'administrateur de votre organisation.",
            },
        },
        'identity.user.deleted': {
            'en': {
                'heading': f'A user account was removed from {company}',
                'paragraphs': [
                    'Email: **{{ data.email }}**',
                    'The account no longer has access to this organization.',
                ],
            },
            'fr': {
                'heading': f'Un compte utilisateur a été retiré de {company}',
                'paragraphs': [
                    'E-mail : **{{ data.email }}**',
                    "Le compte n'a plus accès à cette organisation.",
                ],
            },
        },
        'identity.user.updated': {
            'en': {
                'heading': f'A user profile was updated in {company}',
                'paragraphs': [
                    'Email: **{{ data.email }}**',
                    'Changed fields: {{ data.changed_fields }}',
                ],
            },
            'fr': {
                'heading': f'Un profil utilisateur a été mis à jour dans {company}',
                'paragraphs': [
                    'E-mail : **{{ data.email }}**',
                    'Champs modifiés : {{ data.changed_fields }}',
                ],
            },
        },
        'identity.group.created': {
            'en': {
                'heading': f'A new group was created in {company}',
                'paragraphs': [
                    'Group name: **{{ data.display_name }}**',
                    'Origin: {{ data.source }}',
                ],
            },
            'fr': {
                'heading': f'Un nouveau groupe a été créé dans {company}',
                'paragraphs': [
                    'Nom du groupe : **{{ data.display_name }}**',
                    'Origine : {{ data.source }}',
                ],
            },
        },
        'identity.group.updated': {
            'en': {
                'heading': f'A group was updated in {company}',
                'paragraphs': [
                    'Group name: **{{ data.display_name }}**',
                    'Changed fields: {{ data.changed_fields }}',
                ],
            },
            'fr': {
                'heading': f'Un groupe a été mis à jour dans {company}',
                'paragraphs': [
                    'Nom du groupe : **{{ data.display_name }}**',
                    'Champs modifiés : {{ data.changed_fields }}',
                ],
            },
        },
        'identity.group.deleted': {
            'en': {
                'heading': f'A group was deleted in {company}',
                'paragraphs': [
                    'Group name: **{{ data.display_name }}**',
                ],
            },
            'fr': {
                'heading': f'Un groupe a été supprimé dans {company}',
                'paragraphs': [
                    'Nom du groupe : **{{ data.display_name }}**',
                ],
            },
        },
        'identity.group.membership_changed': {
            'en': {
                'heading': f'Group membership changed in {company}',
                'paragraphs': [
                    'Group: **{{ data.display_name }}**',
                    'Change: {{ data.change }}',
                ],
            },
            'fr': {
                'heading': f"L'adhésion au groupe a changé dans {company}",
                'paragraphs': [
                    'Groupe : **{{ data.display_name }}**',
                    'Modification : {{ data.change }}',
                ],
            },
        },
        'identity.scim.token.created': {
            'en': {
                'heading': f'A new SCIM token was created for {company}',
                'paragraphs': [
                    'Label: **{{ data.name }}**',
                    'Prefix: {{ data.token_prefix }}',
                ],
            },
            'fr': {
                'heading': f'Un nouveau jeton SCIM a été créé pour {company}',
                'paragraphs': [
                    'Libellé : **{{ data.name }}**',
                    'Préfixe : {{ data.token_prefix }}',
                ],
            },
        },
        'identity.scim.token.revoked': {
            'en': {
                'heading': f'A SCIM token was revoked for {company}',
                'paragraphs': [
                    'Label: **{{ data.name }}**',
                    'Prefix: {{ data.token_prefix }}',
                ],
            },
            'fr': {
                'heading': f'Un jeton SCIM a été révoqué pour {company}',
                'paragraphs': [
                    'Libellé : **{{ data.name }}**',
                    'Préfixe : {{ data.token_prefix }}',
                ],
            },
        },
        'identity.auth.magic_link.requested': {
            'en': {
                'heading': "We're almost there!",
                'paragraphs': [
                    f'Thank you for signing in to {company}.',
                    'To continue, confirm with the button below. This link works once and expires soon.',
                ],
                'cta': ('Sign in', '{{ data.magic_link_url }}'),
                'link_fallback': (
                    'If the button does not work, copy this link into your browser:',
                    '{{ data.magic_link_url }}',
                ),
                'footer': 'If you did not request this email, you can ignore it.',
            },
            'fr': {
                'heading': 'Vous y êtes presque !',
                'paragraphs': [
                    f'Merci de vous connecter à {company}.',
                    'Pour continuer, confirmez avec le bouton ci-dessous. Ce lien fonctionne une seule fois et expire bientôt.',
                ],
                'cta': ('Se connecter', '{{ data.magic_link_url }}'),
                'link_fallback': (
                    'Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :',
                    '{{ data.magic_link_url }}',
                ),
                'footer': "Si vous n'avez pas demandé cet e-mail, vous pouvez l'ignorer.",
            },
        },
        'identity.scim.provisioning_conflict': {
            'en': {
                'heading': f'SCIM provisioning needs attention in {company}',
                'paragraphs': [
                    'A provisioning request could not complete because a group with the same display name already exists.',
                    'Display name: **{{ data.display_name }}**',
                    'Requested action: {{ data.operation }}',
                    'Existing group source: {{ data.conflicting_group_source }}',
                    'Rename or merge the groups in your directory, then retry the SCIM request.',
                ],
            },
            'fr': {
                'heading': f'Le provisionnement SCIM nécessite votre attention dans {company}',
                'paragraphs': [
                    "Une demande de provisionnement n'a pas pu aboutir car un groupe portant le même nom existe déjà.",
                    'Nom affiché : **{{ data.display_name }}**',
                    'Action demandée : {{ data.operation }}',
                    'Source du groupe existant : {{ data.conflicting_group_source }}',
                    'Renommez ou fusionnez les groupes dans votre annuaire, puis relancez la requête SCIM.',
                ],
            },
        },
    }
    lang_key = 'en' if en else 'fr'
    return copies[event_id][lang_key]


class Command(BaseCommand):
    help = 'Write React Email JSON defaults for all catalog events.'

    def handle(self, *args, **options):
        root = Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'

        for event in all_event_types():
            for lang in ('en', 'fr'):
                copy = _event_copy(event.id, lang)
                document = _document(
                    kicker='Shellui · {{ envelope.company.name }}',
                    heading=copy['heading'],
                    paragraphs=copy['paragraphs'],
                    cta=copy.get('cta'),
                    link_fallback=copy.get('link_fallback'),
                    footer=copy.get('footer'),
                )
                json_path = root / lang / f'{event.id}.json'
                json_path.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
                self.stdout.write(f'Wrote {json_path.relative_to(settings.BASE_DIR)}')

        self.stdout.write(self.style.SUCCESS('Done.'))
