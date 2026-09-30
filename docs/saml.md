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

Optional: set `metadata_url` instead of manual `sso_url` and `x509cert`. Metadata import uses the same SSRF-pinned HTTP fetch as OAuth discovery (512KB cap).

### IdP-initiated SSO

Off by default (`allow_idp_initiated_sso: false`). Enable only with an explicit risk review: unsolicited responses bypass SP-initiated `InResponseTo` binding.

### Email linking

Default is uid-only account creation. Set `trusted_for_verified_domains: true` on an IdP only when that IdP is trusted for the company `allowed_email_domains` list. Email is never used to link accounts otherwise.

## End-user login

Use the same browser entrypoint as OAuth:

`GET /api/v1/authorize?provider=saml&company_id=…&company_oauth_client_id=…&redirect_to=…`

The user is redirected to the IdP, then back through the company ACS URL.

## Vendor guides

- [Okta SAML app setup](https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm)
- [Microsoft Entra ID SAML SSO](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso)
- [Google Workspace custom SAML apps](https://support.google.com/a/answer/6087519)

Configure the IdP with the SP `entity_id` and `acs_url` from the admin API. Match the IdP entity ID to `idp_entity_id` in Shellui.
