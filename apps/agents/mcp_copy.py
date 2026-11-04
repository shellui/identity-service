"""EN/FR copy for the MCP sign-in, consent, and error pages."""

from __future__ import annotations

COPY = {
    'en': {
        'signin_title': 'Sign in to connect an MCP client',
        'consent_title': 'Allow this MCP client?',
        'error_title': "This connection can't continue",
        'why': '{client} wants to access {company} through the Shellui MCP connector.',
        'why_signin': '{client} wants to access your company through the Shellui MCP connector. Sign in to see which company and approve.',
        'email_sent_generic': 'If this address can sign in here, a sign-in link is on its way. Open it in this browser.',
        'client_label': 'Client name',
        'client_note': 'The client chose this name itself. Shellui does not verify it.',
        'company_label': 'Company',
        'redirect_label': 'After you approve, you go back to',
        'redirect_note': 'Check that you know this address. The client receives its access there.',
        'warning': "If you didn't start this connection yourself, close this page. Don't sign in and don't approve.",
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
        'destructive_label': (
            'Allow destructive changes without asking. Deletes and irreversible actions then run '
            'without a second prompt.'
        ),
        'approve': 'Approve',
        'deny': 'Deny',
        'denied': 'You denied access. You can close this page.',
        'staff_refused': "Staff accounts can't connect MCP clients. Sign in with a company account.",
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
        'signin_title': 'Connectez-vous pour relier un client MCP',
        'consent_title': 'Autoriser ce client MCP ?',
        'error_title': 'Cette connexion ne peut pas continuer',
        'why': '{client} veut accéder à {company} via le connecteur MCP Shellui.',
        'why_signin': "{client} veut accéder à votre entreprise via le connecteur MCP Shellui. Connectez-vous pour voir laquelle et donner votre accord.",
        'email_sent_generic': 'Si cette adresse peut se connecter ici, un lien de connexion arrive. Ouvrez-le dans ce navigateur.',
        'client_label': 'Nom du client',
        'client_note': "Le client a choisi ce nom lui-même. Shellui ne le vérifie pas.",
        'company_label': 'Entreprise',
        'redirect_label': 'Après votre accord, vous revenez sur',
        'redirect_note': 'Vérifiez que vous connaissez cette adresse. Le client y reçoit son accès.',
        'warning': "Si vous n'avez pas lancé cette connexion vous-même, fermez cette page. Ne vous connectez pas et n'autorisez rien.",
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
        'destructive_label': (
            'Autoriser les changements destructifs sans demander. Les suppressions et actions irréversibles '
            "s'exécutent alors sans seconde confirmation."
        ),
        'approve': 'Autoriser',
        'deny': 'Refuser',
        'denied': "Vous avez refusé l'accès. Vous pouvez fermer cette page.",
        'staff_refused': 'Les comptes staff ne peuvent pas relier de client MCP. Connectez-vous avec un compte entreprise.',
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
