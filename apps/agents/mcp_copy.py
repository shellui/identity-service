"""EN/FR copy for the MCP sign-in, consent, and error pages."""

from __future__ import annotations

COPY = {
    'en': {
        'signin_title': 'Sign in to connect an agent',
        'signin_company_name': 'your company',
        'consent_title': 'Allow {client_name}?',
        'consent_body': (
            '{client_name} will call MCP for {company_name} as you. '
            'You can revoke this later in Settings → MCP / AI agents.'
        ),
        'error_title': "This connection can't continue",
        'why_signin': '{client_name} wants to use MCP for {company_name}.',
        'redirect_notice': 'You are leaving this page to sign in on {login_host}.',
        'access_heading': 'Access requested',
        'access_bullet': "Call this company's services over MCP on your behalf",
        'phishing': 'Only continue if you started this from {client_name}.',
        'email_sent_generic': 'If this address can sign in here, a sign-in link is on its way. Open it in this browser.',
        'client_label': 'Client name',
        'client_note': 'The client chose this name itself. Shellui does not verify it.',
        'company_label': 'Company',
        'redirect_label': 'After you approve, you go back to',
        'redirect_note': 'Check that you know this address. The client receives its access there.',
        'methods_title': 'Sign in to {company}',
        'email_label': 'Work email',
        'email_button': 'Email me a sign-in link',
        'email_sent': 'If this address can sign in to {company}, a sign-in link is on its way. Open it in this browser.',
        'provider_button': 'Continue with {provider}',
        'no_methods': "{company} has no sign-in method that works here. Ask your administrator.",
        'signed_in_as': 'Signed in as {email}',
        'services_label': 'Services the client can use',
        'access_label': 'Access level',
        'read_label': 'Data it can read',
        'agent_name_label': 'Agent name',
        'saas_opt_in_label': 'Also allow SaaS tools (global Shellui account sign-in required)',
        'saas_opt_in_note': (
            'When checked, you sign in on global Shellui before approval. The regional agent can '
            'call SaaS through token exchange.'
        ),
        'allow': 'Allow',
        'deny': 'Deny',
        'cancel': 'Cancel',
        'denied': 'You denied access. You can close this page.',
        'staff_refused': 'Staff accounts cannot authorize MCP agents. Sign in with a company account.',
        'not_member': "Your account isn't a member of {company}.",
        'session_lost': 'Open the sign-in link in the browser where you started, then try again.',
        'start_again': 'Start the connection again from your MCP client.',
        'access_read_only': 'Read only',
        'access_ask': 'Ask before changes',
        'access_full': 'Full access',
        'read_safe': 'Safe (personal data masked)',
        'read_sensitive': 'Sensitive data',
    },
    'fr': {
        'signin_title': 'Connectez-vous pour relier un agent',
        'signin_company_name': 'votre entreprise',
        'consent_title': 'Autoriser {client_name} ?',
        'consent_body': (
            '{client_name} appellera MCP pour {company_name} en votre nom. '
            'Vous pourrez révoquer cela plus tard dans Réglages → MCP / agents IA.'
        ),
        'error_title': 'Cette connexion ne peut pas continuer',
        'why_signin': '{client_name} veut utiliser MCP pour {company_name}.',
        'redirect_notice': 'Vous quittez cette page pour vous connecter sur {login_host}.',
        'access_heading': 'Accès demandé',
        'access_bullet': 'Appeler les services de cette entreprise via MCP en votre nom',
        'phishing': 'Continuez seulement si vous avez lancé cette demande depuis {client_name}.',
        'email_sent_generic': 'Si cette adresse peut se connecter ici, un lien de connexion arrive. Ouvrez-le dans ce navigateur.',
        'client_label': 'Nom du client',
        'client_note': "Le client a choisi ce nom lui-même. Shellui ne le vérifie pas.",
        'company_label': 'Entreprise',
        'redirect_label': 'Après votre accord, vous revenez sur',
        'redirect_note': 'Vérifiez que vous connaissez cette adresse. Le client y reçoit son accès.',
        'methods_title': 'Connexion à {company}',
        'email_label': 'E-mail professionnel',
        'email_button': "M'envoyer un lien de connexion",
        'email_sent': 'Si cette adresse peut se connecter à {company}, un lien de connexion arrive. Ouvrez-le dans ce navigateur.',
        'provider_button': 'Continuer avec {provider}',
        'no_methods': "{company} n'a aucune méthode de connexion utilisable ici. Contactez votre administrateur.",
        'signed_in_as': 'Connecté en tant que {email}',
        'services_label': 'Services que le client peut utiliser',
        'access_label': "Niveau d'accès",
        'read_label': 'Données lisibles',
        'agent_name_label': "Nom de l'agent",
        'saas_opt_in_label': 'Autoriser aussi les outils SaaS (connexion au compte Shellui global requise)',
        'saas_opt_in_note': (
            'Si coché, vous vous connectez sur Shellui global avant l\'accord. L\'agent régional pourra '
            'appeler SaaS via l\'échange de jetons.'
        ),
        'allow': 'Autoriser',
        'deny': 'Refuser',
        'cancel': 'Annuler',
        'denied': "Vous avez refusé l'accès. Vous pouvez fermer cette page.",
        'staff_refused': (
            'Les comptes staff ne peuvent pas autoriser des agents MCP. Connectez-vous avec un compte entreprise.'
        ),
        'not_member': "Votre compte n'est pas membre de {company}.",
        'session_lost': 'Ouvrez le lien de connexion dans le navigateur où vous avez commencé, puis réessayez.',
        'start_again': 'Relancez la connexion depuis votre client MCP.',
        'access_read_only': 'Lecture seule',
        'access_ask': 'Demander avant les changements',
        'access_full': 'Accès complet',
        'read_safe': 'Standard (données personnelles masquées)',
        'read_sensitive': 'Données sensibles',
    },
}

ERRORS = {
    'en': {
        'invalid_client': 'This MCP client is unknown. Shellui did not send you anywhere.',
        'invalid_redirect_uri': "The return address doesn't match the one this client registered. Shellui did not send you anywhere.",
        'invalid_resource': 'The MCP URL is not valid. Use the per-company URL: /c/<company_id>/mcp.',
        'company_required': 'This MCP URL has no company. Use the per-company URL: /c/<company_id>/mcp.',
        'unknown_company': 'This company is not available.',
        'invalid_request': 'The request is missing a required value.',
        'registration_disabled': 'This company does not allow new MCP clients.',
    },
    'fr': {
        'invalid_client': "Ce client MCP est inconnu. Shellui ne vous a redirigé nulle part.",
        'invalid_redirect_uri': "L'adresse de retour ne correspond pas à celle enregistrée par ce client. Shellui ne vous a redirigé nulle part.",
        'invalid_resource': "L'URL MCP n'est pas valide. Utilisez l'URL par entreprise : /c/<company_id>/mcp.",
        'company_required': "Cette URL MCP n'indique pas d'entreprise. Utilisez l'URL par entreprise : /c/<company_id>/mcp.",
        'unknown_company': "Cette entreprise n'est pas disponible.",
        'invalid_request': 'Il manque une valeur obligatoire dans la requête.',
        'registration_disabled': "Cette entreprise n'autorise pas de nouveaux clients MCP.",
    },
}


def copy_for(lang: str) -> dict[str, str]:
    return COPY.get(lang) or COPY['en']


def error_message(lang: str, code: str) -> str:
    table = ERRORS.get(lang) or ERRORS['en']
    return table.get(code) or ERRORS['en'].get(code) or ERRORS['en']['invalid_request']
