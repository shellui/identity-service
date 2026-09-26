"""Generate flat HTML + React Email editor JSON defaults (maintainer utility)."""

from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.actions.registry import all_event_types

# Shellui calm palette: zinc neutrals, gold accent used sparingly in links only.


def _text_node(text: str) -> dict:
    return {'type': 'text', 'text': text}


def _paragraph(text: str) -> dict:
    return {'type': 'paragraph', 'content': [_text_node(text)]}


def _heading(level: int, text: str) -> dict:
    return {'type': 'heading', 'attrs': {'level': level}, 'content': [_text_node(text)]}


def _button(label: str, href: str) -> dict:
    return {
        'type': 'paragraph',
        'content': [
            {
                'type': 'text',
                'text': label,
                'marks': [{'type': 'link', 'attrs': {'href': href, 'target': '_blank'}}],
            }
        ],
    }


def _document(
    *,
    html_lang: str,
    title: str,
    kicker: str,
    heading: str,
    paragraphs: list[str],
    cta: tuple[str, str] | None = None,
    footer: str | None = None,
) -> tuple[str, dict]:
    doc_content: list[dict] = [
        _paragraph(kicker),
        _heading(1, heading),
    ]
    for para in paragraphs:
        doc_content.append(_paragraph(para))
    if cta:
        doc_content.append(_button(cta[0], cta[1]))
    if footer:
        doc_content.append(_paragraph(footer))

    document = {'type': 'doc', 'content': doc_content}

    body_parts: list[str] = []
    for para in paragraphs:
        body_parts.append(
            f'  <p style="margin: 0 0 16px; font-size: 15px; color: #3f3f46;">{para}</p>'
        )
    cta_html = ''
    if cta:
        cta_html = (
            f'  <p style="margin: 0 0 20px;">'
            f'<a href="{cta[1]}" style="display: inline-block; background-color: #18181b; '
            f'color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 9999px; '
            f'font-weight: 600; font-size: 15px;">{cta[0]}</a></p>'
        )
    footer_html = ''
    if footer:
        footer_html = (
            f'  <p style="margin: 28px 0 0; padding-top: 20px; border-top: 1px solid #f4f4f5; '
            f'color: #a1a1aa; font-size: 12px; line-height: 1.5;">{footer}</p>'
        )

    html = f"""<!DOCTYPE html>
<html lang="{html_lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f5; color: #18181b; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; line-height: 1.5; -webkit-font-smoothing: antialiased;">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f4f4f5; border-collapse: collapse;">
    <tr>
      <td align="center" style="padding: 32px 16px;">
        <table role="presentation" cellpadding="0" cellspacing="0" width="560" style="max-width: 560px; width: 100%; background-color: #ffffff; border: 1px solid #e4e4e7; border-radius: 10px; border-collapse: separate;">
          <tr>
            <td style="padding: 32px 28px;">
              <p style="margin: 0 0 24px; color: #71717a; font-size: 13px;">{kicker}</p>
              <h1 style="margin: 0 0 16px; font-size: 22px; font-weight: 600; letter-spacing: -0.02em; color: #18181b;">{heading}</h1>
{chr(10).join(body_parts)}
{cta_html}
{footer_html}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
    return html, document


def _event_copy(event_id: str, lang: str) -> dict:
    company = '{{ envelope.company.name }}'
    en = lang == 'en'
    copies: dict[str, dict[str, dict]] = {
        'identity.scim.user.provisioned': {
            'en': {
                'title': 'Access enabled',
                'heading': f'You have access to {company}',
                'paragraphs': [
                    f'Your organization enabled your access. Sign in with <strong style="font-weight: 600;">{{{{ data.email }}}}</strong> when your app is ready.',
                    'If you already had an account elsewhere in Shellui, use the same email address.',
                ],
                'footer': "Questions? Contact your organization's administrator.",
            },
            'fr': {
                'title': 'Accès activé',
                'heading': f'Vous avez accès à {company}',
                'paragraphs': [
                    f'Votre organisation a activé votre accès. Connectez-vous avec <strong style="font-weight: 600;">{{{{ data.email }}}}</strong> lorsque votre application est prête.',
                    'Si vous aviez déjà un compte ailleurs dans Shellui, utilisez la même adresse e-mail.',
                ],
                'footer': "Des questions ? Contactez l'administrateur de votre organisation.",
            },
        },
        'identity.scim.user.deprovisioned': {
            'en': {
                'title': 'Access ended',
                'heading': f'Your access to {company} has ended',
                'paragraphs': [
                    f'You no longer have access to this organization ({{{{ data.email }}}}). Your Shellui account was not deleted and may still work for other organizations.',
                    "If this looks wrong, contact your organization's administrator.",
                ],
            },
            'fr': {
                'title': 'Accès terminé',
                'heading': f'Votre accès à {company} est terminé',
                'paragraphs': [
                    f'Vous n\'avez plus accès à cette organisation ({{{{ data.email }}}}). Votre compte Shellui n\'a pas été supprimé et peut encore fonctionner pour d\'autres organisations.',
                    "Si cela vous semble incorrect, contactez l'administrateur de votre organisation.",
                ],
            },
        },
        'identity.user.created': {
            'en': {
                'title': 'Welcome',
                'heading': f'Welcome to {company}',
                'paragraphs': [
                    f'An account for <strong style="font-weight: 600;">{{{{ data.email }}}}</strong> is ready. Sign in when your administrator shares the link to your app.',
                    'You can continue with {{ data.oauth_provider }} on the sign-in page when OAuth is enabled.',
                ],
                'footer': "If you did not expect this message, contact your organization's administrator.",
            },
            'fr': {
                'title': 'Bienvenue',
                'heading': f'Bienvenue chez {company}',
                'paragraphs': [
                    f'Un compte pour <strong style="font-weight: 600;">{{{{ data.email }}}}</strong> est prêt. Connectez-vous lorsque votre administrateur partage le lien vers votre application.',
                    'Vous pouvez continuer avec {{ data.oauth_provider }} sur la page de connexion lorsque OAuth est activé.',
                ],
                'footer': "Si vous n'attendiez pas ce message, contactez l'administrateur de votre organisation.",
            },
        },
        'identity.user.deleted': {
            'en': {
                'title': 'Account removed',
                'heading': f'A user account was removed from {company}',
                'paragraphs': [
                    'Email: <strong style="font-weight: 600;">{{ data.email }}</strong>',
                    'The account no longer has access to this organization.',
                ],
            },
            'fr': {
                'title': 'Compte supprimé',
                'heading': f'Un compte utilisateur a été retiré de {company}',
                'paragraphs': [
                    'E-mail : <strong style="font-weight: 600;">{{ data.email }}</strong>',
                    "Le compte n'a plus accès à cette organisation.",
                ],
            },
        },
        'identity.user.updated': {
            'en': {
                'title': 'Profile updated',
                'heading': f'A user profile was updated in {company}',
                'paragraphs': [
                    'Email: <strong style="font-weight: 600;">{{ data.email }}</strong>',
                    'Changed fields: {{ data.changed_fields }}',
                ],
            },
            'fr': {
                'title': 'Profil mis à jour',
                'heading': f'Un profil utilisateur a été mis à jour dans {company}',
                'paragraphs': [
                    'E-mail : <strong style="font-weight: 600;">{{ data.email }}</strong>',
                    'Champs modifiés : {{ data.changed_fields }}',
                ],
            },
        },
        'identity.group.created': {
            'en': {
                'title': 'Group created',
                'heading': f'A new group was created in {company}',
                'paragraphs': [
                    'Group name: <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Origin: {{ data.source }}',
                ],
            },
            'fr': {
                'title': 'Groupe créé',
                'heading': f'Un nouveau groupe a été créé dans {company}',
                'paragraphs': [
                    'Nom du groupe : <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Origine : {{ data.source }}',
                ],
            },
        },
        'identity.group.updated': {
            'en': {
                'title': 'Group updated',
                'heading': f'A group was updated in {company}',
                'paragraphs': [
                    'Group name: <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Changed fields: {{ data.changed_fields }}',
                ],
            },
            'fr': {
                'title': 'Groupe mis à jour',
                'heading': f'Un groupe a été mis à jour dans {company}',
                'paragraphs': [
                    'Nom du groupe : <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Champs modifiés : {{ data.changed_fields }}',
                ],
            },
        },
        'identity.group.deleted': {
            'en': {
                'title': 'Group deleted',
                'heading': f'A group was deleted in {company}',
                'paragraphs': [
                    'Group name: <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                ],
            },
            'fr': {
                'title': 'Groupe supprimé',
                'heading': f'Un groupe a été supprimé dans {company}',
                'paragraphs': [
                    'Nom du groupe : <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                ],
            },
        },
        'identity.group.membership_changed': {
            'en': {
                'title': 'Membership changed',
                'heading': f'Group membership changed in {company}',
                'paragraphs': [
                    'Group: <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Change: {{ data.change }}',
                ],
            },
            'fr': {
                'title': 'Adhésion modifiée',
                'heading': f"L'adhésion au groupe a changé dans {company}",
                'paragraphs': [
                    'Groupe : <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Modification : {{ data.change }}',
                ],
            },
        },
        'identity.scim.token.created': {
            'en': {
                'title': 'SCIM token created',
                'heading': f'A new SCIM token was created for {company}',
                'paragraphs': [
                    'Label: <strong style="font-weight: 600;">{{ data.name }}</strong>',
                    'Prefix: {{ data.token_prefix }}',
                ],
            },
            'fr': {
                'title': 'Jeton SCIM créé',
                'heading': f'Un nouveau jeton SCIM a été créé pour {company}',
                'paragraphs': [
                    'Libellé : <strong style="font-weight: 600;">{{ data.name }}</strong>',
                    'Préfixe : {{ data.token_prefix }}',
                ],
            },
        },
        'identity.scim.token.revoked': {
            'en': {
                'title': 'SCIM token revoked',
                'heading': f'A SCIM token was revoked for {company}',
                'paragraphs': [
                    'Label: <strong style="font-weight: 600;">{{ data.name }}</strong>',
                    'Prefix: {{ data.token_prefix }}',
                ],
            },
            'fr': {
                'title': 'Jeton SCIM révoqué',
                'heading': f'Un jeton SCIM a été révoqué pour {company}',
                'paragraphs': [
                    'Libellé : <strong style="font-weight: 600;">{{ data.name }}</strong>',
                    'Préfixe : {{ data.token_prefix }}',
                ],
            },
        },
        'identity.auth.magic_link.requested': {
            'en': {
                'title': 'Sign in',
                'heading': f'Sign in to {company}',
                'paragraphs': [
                    f'You requested a sign-in link for {company}. Use the button below to continue.',
                    'This link works once and expires soon.',
                    'If the button does not work, copy this link into your browser:<br><span style="word-break: break-all; color: #52525b;">{{ data.magic_link_url }}</span>',
                ],
                'cta': ('Sign in', '{{ data.magic_link_url }}'),
                'footer': 'If you did not request this email, you can ignore it.',
            },
            'fr': {
                'title': 'Connexion',
                'heading': f'Connectez-vous à {company}',
                'paragraphs': [
                    f'Vous avez demandé un lien de connexion pour {company}. Utilisez le bouton ci-dessous pour continuer.',
                    'Ce lien fonctionne une seule fois et expire bientôt.',
                    'Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :<br><span style="word-break: break-all; color: #52525b;">{{ data.magic_link_url }}</span>',
                ],
                'cta': ('Se connecter', '{{ data.magic_link_url }}'),
                'footer': "Si vous n'avez pas demandé cet e-mail, vous pouvez l'ignorer.",
            },
        },
        'identity.scim.provisioning_conflict': {
            'en': {
                'title': 'SCIM conflict',
                'heading': f'SCIM provisioning needs attention in {company}',
                'paragraphs': [
                    'A provisioning request could not complete because a group with the same display name already exists.',
                    'Display name: <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
                    'Requested action: {{ data.operation }}',
                    'Existing group source: {{ data.conflicting_group_source }}',
                    'Rename or merge the groups in your directory, then retry the SCIM request.',
                ],
            },
            'fr': {
                'title': 'Conflit SCIM',
                'heading': f'Le provisionnement SCIM nécessite votre attention dans {company}',
                'paragraphs': [
                    'Une demande de provisionnement n\'a pas pu aboutir car un groupe portant le même nom existe déjà.',
                    'Nom affiché : <strong style="font-weight: 600;">{{ data.display_name }}</strong>',
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
    help = 'Write flat HTML and React Email JSON defaults for all catalog events.'

    def handle(self, *args, **options):
        root = Path(settings.BASE_DIR) / 'apps/actions/templates/actions/emails'
        layout = root / '_layout.html'
        if layout.is_file():
            layout.unlink()

        for event in all_event_types():
            for lang in ('en', 'fr'):
                copy = _event_copy(event.id, lang)
                kicker = 'Shellui · {{ envelope.company.name }}'
                html, document = _document(
                    html_lang=lang,
                    title=copy['title'],
                    kicker=kicker,
                    heading=copy['heading'],
                    paragraphs=copy['paragraphs'],
                    cta=copy.get('cta'),
                    footer=copy.get('footer'),
                )
                html_path = root / lang / f'{event.id}.html'
                json_path = root / lang / f'{event.id}.json'
                html_path.write_text(html, encoding='utf-8')
                json_path.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
                self.stdout.write(f'Wrote {html_path.relative_to(settings.BASE_DIR)}')

        self.stdout.write(self.style.SUCCESS('Done.'))
