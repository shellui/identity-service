# SAML 2.0 single sign-on

Shellui identity-service acts as the SAML service provider (SP). Each company can register one or more SAML identity providers (IdPs), such as Okta, Microsoft Entra ID, Google Workspace, or ADFS.

## Admin setup (API)

1. Open `GET /api/v1/oauth-provider-catalog` and confirm the `saml` entry is `supported: true`.
2. Create an IdP with `POST /api/v1/oauth-social-apps`:
   - `docs_slug`: `saml`
   - `extra_settings`: IdP fields (see catalog `extra_settings_schema`)
3. Read `saml` from the created `social_app` payload:
   - `entity_id`: SP entity ID to paste into the IdP
   - `acs_url`: assertion consumer service URL
   - `metadata_url`: SP metadata XML for import
4. In the IdP, map attributes for `uid`, email, and optional name fields to match your `attribute_mapping`.

Optional: set `metadata_url` instead of manual `sso_url` and `x509cert`. On save, Shellui fetches that URL (same SSRF-pinned HTTP client as OAuth discovery, 512KB cap), stores the redirect SSO URL, and keeps a signing certificate (`KeyDescriptor` use `signing`, or a key with no use). An encryption-only certificate is rejected with `saml_metadata_missing_certificate`. Imported and manual `sso_url` / `slo_url` values must be public HTTPS URLs.

### Account isolation

Each SAML SocialApp belongs to one company, and that mapping cannot move to another company. SocialAccount rows use `saml-{social_app_id}`, not the bare provider id `saml`. The same IdP entity ID cannot be registered for two different companies (`saml_idp_entity_id_in_use`).

Changing `client_id` (the organization slug) on PUT is rejected with `oauth_app_client_id_taken` when another SocialApp already has that value. A slug that matches more than one SAML app returns 404 (`saml_app_not_found`) instead of a server error.

### ACS hardening

- `strict` and signed assertions are always enforced; admin `advanced` settings cannot weaken them.
- `InResponseTo` is single-use, bound to the browser session that started login, and passed into SAML response validation.
- Assertion replay IDs are stored in the shared Django cache with TTL tied to the assertion `NotOnOrAfter` (max 15 minutes). LocMemCache is allowed in DEBUG only; production must use a shared cache backend.
- SP-initiated login at `/api/v1/saml/organization_slug/login/` validates `redirect_to` the same way as `/api/v1/authorize`. `token_delivery` accepts `code` or `fragment` and ignores any other value, matching authorize. The server default is `OAUTH_TOKEN_DELIVERY`.
- ACS failures return JSON `{"error_code": "..."}`. A transient NameID used as the account id returns `saml_nameid_transient`. An assertion with no email returns `saml_email_required`. Shellui does not invent an email.
- A successful login is recorded once, when the confirm step completes (or when confirm is skipped).
- An assertion with no `Audience` returns `saml_audience_missing`.

### Logout

IdP-initiated logout at the SLS URL requires a signed logout request. When the NameID matches a SAML SocialAccount for that IdP, Shellui revokes that user's refresh sessions for the IdP's company.

### IdP-initiated SSO

Off by default (`allow_idp_initiated_sso: false`). Enable only with an explicit risk review: unsolicited responses bypass SP-initiated `InResponseTo` binding.

### Email linking

Default is uid-only account creation. IdP `email_verified` (or similar) attributes never enable linking.

The only exception is when all of the following hold:

1. The IdP has `trusted_for_verified_domains: true`.
2. The assertion email domain is listed in the company `verified_email_domains` field (Shellui domain verification, not `allowed_email_domains`).
3. The email is not already tied to another user under a different SAML uid (`saml_email_conflict`).

### Domain verification (platform only)

`verified_email_domains` is **not** writable through the company admin API. Shellui operators set it in Django admin after confirming domain ownership (DNS TXT self-service verification is planned separately). Company owners cannot self-assert a domain to unlock SAML email linking.

## End-user login

Use the same browser entrypoint as OAuth:

`GET /api/v1/authorize?provider=saml&company_id=…&company_oauth_client_id=…&redirect_to=…`

The user is redirected to the IdP, then back through the company ACS URL.

## Vendor guides

- [Okta SAML app setup](https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm)
- [Microsoft Entra ID SAML SSO](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso)
- [Google Workspace custom SAML apps](https://support.google.com/a/answer/6087519)

Configure the IdP with the SP `entity_id` and `acs_url` from the admin API. Match the IdP entity ID to `idp_entity_id` in Shellui.
