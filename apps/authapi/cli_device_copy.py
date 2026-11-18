"""EN/FR copy for the Shellui CLI device sign-in pages."""

from __future__ import annotations

COPY = {
    'en': {
        'title': 'Sign in the Shellui CLI on another device',
        'error_title': 'This sign-in cannot continue',
        'code_lead': 'The Shellui CLI showed a code. Enter it here to continue.',
        'code_lead_prefilled': 'Confirm the code from the Shellui CLI. Change it if it does not match.',
        'code_label': 'Code',
        'code_hint': 'Eight letters or digits, with or without the hyphen.',
        'continue': 'Continue',
        'signin_lead': 'Sign in to {company} to approve the Shellui CLI.',
        'staff_note': (
            'Staff accounts sign in with a password or single sign-on. '
            'An email link is not sent to a staff account.'
        ),
        'email_label': 'Work email',
        'email_button': 'Email me a sign-in link',
        'email_sent': (
            'If this address can sign in to {company}, a sign-in link is on its way. Open it in this browser.'
        ),
        'email_unavailable': 'This company does not send email sign-in links. Use a password or single sign-on.',
        'password_heading': 'Password',
        'password_label': 'Password',
        'password_button': 'Sign in with a password',
        'password_failed': 'That email and password did not match.',
        'provider_heading': 'Single sign-on',
        'provider_button': 'Continue with {provider}',
        'signed_in_as': 'Signed in as {email}',
        'company_label': 'Company',
        'requested_at_label': 'Requested at',
        'ip_label': 'Requesting IP',
        'ua_label': 'User agent',
        'code_check_label': 'Code',
        'unknown': 'Unknown',
        'allow': 'Allow',
        'deny': 'Deny',
        'approved_title': 'CLI signed in',
        'approved': (
            'You approved the Shellui CLI. You can close this page. The CLI finishes signing in from its side.'
        ),
        'denied': 'You denied access. You can close this page.',
        'staff_magic_refused': (
            'Staff accounts sign in with a password or single sign-on. An email link cannot approve the Shellui CLI.'
        ),
        'not_member': 'Your account is not a member of {company}.',
        'access_disabled': 'Company access is disabled. Contact an administrator.',
        'session_lost': 'Open the sign-in link in the browser where you started, then try again.',
        'start_again': 'Start sign-in again from the Shellui CLI.',
    },
    'fr': {
        'title': 'Connecter le CLI Shellui sur un autre appareil',
        'error_title': 'Cette connexion ne peut pas continuer',
        'code_lead': 'Le CLI Shellui a affiché un code. Saisissez-le ici pour continuer.',
        'code_lead_prefilled': "Confirmez le code du CLI Shellui. Modifiez-le s'il ne correspond pas.",
        'code_label': 'Code',
        'code_hint': "Huit lettres ou chiffres, avec ou sans le trait d'union.",
        'continue': 'Continuer',
        'signin_lead': 'Connectez-vous à {company} pour approuver le CLI Shellui.',
        'staff_note': (
            "Les comptes staff se connectent avec un mot de passe ou l'authentification unique. "
            "Aucun lien par e-mail n'est envoyé à un compte staff."
        ),
        'email_label': 'E-mail professionnel',
        'email_button': "M'envoyer un lien de connexion",
        'email_sent': (
            'Si cette adresse peut se connecter à {company}, un lien de connexion arrive. '
            'Ouvrez-le dans ce navigateur.'
        ),
        'email_unavailable': (
            "Cette entreprise n'envoie pas de lien de connexion par e-mail. "
            "Utilisez un mot de passe ou l'authentification unique."
        ),
        'password_heading': 'Mot de passe',
        'password_label': 'Mot de passe',
        'password_button': 'Se connecter avec un mot de passe',
        'password_failed': 'Cet e-mail et ce mot de passe ne correspondent pas.',
        'provider_heading': 'Authentification unique',
        'provider_button': 'Continuer avec {provider}',
        'signed_in_as': 'Connecté en tant que {email}',
        'company_label': 'Entreprise',
        'requested_at_label': 'Demandé à',
        'ip_label': 'Adresse IP de la demande',
        'ua_label': 'Agent utilisateur',
        'code_check_label': 'Code',
        'unknown': 'Inconnu',
        'allow': 'Autoriser',
        'deny': 'Refuser',
        'approved_title': 'CLI connecté',
        'approved': (
            'Vous avez approuvé le CLI Shellui. Vous pouvez fermer cette page. '
            'Le CLI termine la connexion de son côté.'
        ),
        'denied': "Vous avez refusé l'accès. Vous pouvez fermer cette page.",
        'staff_magic_refused': (
            "Les comptes staff se connectent avec un mot de passe ou l'authentification unique. "
            'Un lien par e-mail ne peut pas approuver le CLI Shellui.'
        ),
        'not_member': "Votre compte n'est pas membre de {company}.",
        'access_disabled': "L'accès à cette entreprise est désactivé. Contactez un administrateur.",
        'session_lost': 'Ouvrez le lien de connexion dans le navigateur où vous avez commencé, puis réessayez.',
        'start_again': 'Relancez la connexion depuis le CLI Shellui.',
    },
}

ERRORS = {
    'en': {
        'invalid_request': 'The request is missing a required value.',
        'device_code_invalid': 'That code is not valid. Check it and try again.',
        'device_code_expired': 'That code has expired. Start again from the Shellui CLI.',
        'device_code_used': 'That code was already used.',
        'device_code_denied': 'That request was denied. Start again from the Shellui CLI.',
    },
    'fr': {
        'invalid_request': 'Il manque une valeur obligatoire dans la requête.',
        'device_code_invalid': "Ce code n'est pas valide. Vérifiez-le et réessayez.",
        'device_code_expired': 'Ce code a expiré. Relancez la demande depuis le CLI Shellui.',
        'device_code_used': 'Ce code a déjà été utilisé.',
        'device_code_denied': 'Cette demande a été refusée. Relancez-la depuis le CLI Shellui.',
    },
}


def copy_for(lang: str) -> dict[str, str]:
    return COPY.get(lang) or COPY['en']


def error_message(lang: str, code: str) -> str:
    table = ERRORS.get(lang) or ERRORS['en']
    return table.get(code) or ERRORS['en'].get(code) or ERRORS['en']['invalid_request']
