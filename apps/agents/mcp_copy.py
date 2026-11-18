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
        'device_title': 'Enter the code from your agent',
        'device_lead': 'Your agent showed a code. Enter it here to connect it to your company.',
        'device_lead_prefilled': 'Confirm the code from your agent. Change it if it does not match.',
        'device_code_label': 'Code',
        'device_code_hint': 'Eight letters or digits, with or without the hyphen.',
        'device_continue': 'Continue',
        'device_approved_title': 'Agent connected',
        'device_approved': (
            'You approved this agent. You can close this page. The agent finishes connecting from its side.'
        ),
        'device_lifetime_note': (
            'This connection expires after {days} days. You can revoke it sooner in Settings → MCP / AI agents.'
        ),
        'approval_signin_title': 'Sign in to decide this request',
        'approval_signin_lead': '{agent_name} wants to run {tool_name} for {company_name}. Sign in to decide.',
        'approval_title_pending': 'Approve this action?',
        'approval_title_approved': 'Approved',
        'approval_title_denied': 'Denied',
        'approval_title_expired': 'This approval is no longer valid',
        'approval_title_unknown': 'This approval was not found',
        'approval_title_unavailable': 'This request cannot be decided here',
        'approval_title_wrong': 'This account cannot decide this request',
        'approval_lead': '{agent_name} wants to run {tool_name} on {company_name}.',
        'approval_company': 'Company',
        'approval_agent': 'Agent',
        'approval_client': 'Client',
        'approval_service': 'Service',
        'approval_tool': 'Tool',
        'approval_arguments': 'Arguments',
        'approval_arguments_empty': 'No argument summary was included.',
        'approval_expires': 'Expires',
        'approval_destructive': 'This can change or delete data in {company_name}.',
        'approval_not_destructive': 'This tool is not marked as destructive.',
        'approval_safety': 'Only continue if you started this from {agent_name}.',
        'approval_approve': 'Approve',
        'approval_deny': 'Deny',
        'approval_approved_body': (
            'You approved this action. {agent_name} will keep working — you can close this page.'
        ),
        'approval_denied_body': (
            'You denied this action. Nothing was changed. You can return to {agent_name}.'
        ),
        'approval_expired_body': 'This request expired before a decision. Ask the agent to send a new one.',
        'approval_already_approved': (
            'This request was already approved. {agent_name} will keep working — you can close this page.'
        ),
        'approval_already_denied': 'This request was already denied. Nothing was changed.',
        'approval_unknown_body': 'This link does not match an approval request.',
        'approval_unavailable_body': 'This request has no company page. Decide it in Shellui if you still can.',
        'approval_wrong_body': 'Sign in with an account that can decide this request for {company_name}.',
        'approval_footer': 'You can also review pending approvals in Settings, under MCP / AI agents.',
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
        'device_title': 'Saisissez le code de votre agent',
        'device_lead': 'Votre agent a affiché un code. Saisissez-le ici pour le connecter à votre entreprise.',
        'device_lead_prefilled': "Confirmez le code de votre agent. Modifiez-le s'il ne correspond pas.",
        'device_code_label': 'Code',
        'device_code_hint': "Huit lettres ou chiffres, avec ou sans le trait d'union.",
        'device_continue': 'Continuer',
        'device_approved_title': 'Agent connecté',
        'device_approved': (
            'Vous avez approuvé cet agent. Vous pouvez fermer cette page. '
            "L'agent termine la connexion de son côté."
        ),
        'device_lifetime_note': (
            'Cette connexion expire au bout de {days} jours. '
            'Vous pouvez la révoquer plus tôt dans Réglages → MCP / agents IA.'
        ),
        'approval_signin_title': 'Connectez-vous pour décider de cette demande',
        'approval_signin_lead': (
            '{agent_name} veut exécuter {tool_name} pour {company_name}. Connectez-vous pour décider.'
        ),
        'approval_title_pending': 'Approuver cette action ?',
        'approval_title_approved': 'Approuvée',
        'approval_title_denied': 'Refusée',
        'approval_title_expired': "Cette approbation n'est plus valable",
        'approval_title_unknown': 'Cette approbation est introuvable',
        'approval_title_unavailable': 'Cette demande ne peut pas être décidée ici',
        'approval_title_wrong': 'Ce compte ne peut pas décider de cette demande',
        'approval_lead': '{agent_name} veut exécuter {tool_name} pour {company_name}.',
        'approval_company': 'Entreprise',
        'approval_agent': 'Agent',
        'approval_client': 'Client',
        'approval_service': 'Service',
        'approval_tool': 'Outil',
        'approval_arguments': 'Arguments',
        'approval_arguments_empty': "Aucun résumé des arguments n'a été inclus.",
        'approval_expires': 'Expiration',
        'approval_destructive': 'Cela peut modifier ou supprimer des données dans {company_name}.',
        'approval_not_destructive': "Cet outil n'est pas marqué comme destructif.",
        'approval_safety': "Continuez seulement si vous avez lancé cette demande depuis {agent_name}.",
        'approval_approve': 'Approuver',
        'approval_deny': 'Refuser',
        'approval_approved_body': (
            'Vous avez approuvé cette action. {agent_name} continue son travail — vous pouvez fermer cette page.'
        ),
        'approval_denied_body': (
            "Vous avez refusé cette action. Rien n'a été modifié. Vous pouvez revenir à {agent_name}."
        ),
        'approval_expired_body': (
            "Cette demande a expiré avant une décision. Demandez à l'agent d'en envoyer une nouvelle."
        ),
        'approval_already_approved': (
            'Cette demande a déjà été approuvée. {agent_name} continue son travail — vous pouvez fermer cette page.'
        ),
        'approval_already_denied': "Cette demande a déjà été refusée. Rien n'a été modifié.",
        'approval_unknown_body': "Ce lien ne correspond à aucune demande d'approbation.",
        'approval_unavailable_body': (
            "Cette demande n'a pas de page d'entreprise. Décidez-la dans Shellui si vous le pouvez encore."
        ),
        'approval_wrong_body': 'Connectez-vous avec un compte qui peut décider de cette demande pour {company_name}.',
        'approval_footer': (
            'Vous pouvez aussi revoir les approbations en attente dans Réglages, sous MCP / agents IA.'
        ),
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
        'device_code_invalid': 'That code is not valid. Check it and try again.',
        'device_code_expired': 'That code has expired. Start again from the agent.',
        'device_code_used': 'That code was already used.',
        'device_code_denied': 'That request was denied. Start again from the agent.',
    },
    'fr': {
        'invalid_client': "Ce client MCP est inconnu. Shellui ne vous a redirigé nulle part.",
        'invalid_redirect_uri': "L'adresse de retour ne correspond pas à celle enregistrée par ce client. Shellui ne vous a redirigé nulle part.",
        'invalid_resource': "L'URL MCP n'est pas valide. Utilisez l'URL par entreprise : /c/<company_id>/mcp.",
        'company_required': "Cette URL MCP n'indique pas d'entreprise. Utilisez l'URL par entreprise : /c/<company_id>/mcp.",
        'unknown_company': "Cette entreprise n'est pas disponible.",
        'invalid_request': 'Il manque une valeur obligatoire dans la requête.',
        'registration_disabled': "Cette entreprise n'autorise pas de nouveaux clients MCP.",
        'device_code_invalid': "Ce code n'est pas valide. Vérifiez-le et réessayez.",
        'device_code_expired': "Ce code a expiré. Relancez la demande depuis l'agent.",
        'device_code_used': 'Ce code a déjà été utilisé.',
        'device_code_denied': "Cette demande a été refusée. Relancez-la depuis l'agent.",
    },
}


def copy_for(lang: str) -> dict[str, str]:
    return COPY.get(lang) or COPY['en']


def error_message(lang: str, code: str) -> str:
    table = ERRORS.get(lang) or ERRORS['en']
    return table.get(code) or ERRORS['en'].get(code) or ERRORS['en']['invalid_request']
