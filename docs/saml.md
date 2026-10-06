---
description: Set up SAML 2.0 single sign-on for a company with Okta, Microsoft Entra ID, Google Workspace, or ADFS, and how identity-service validates assertions.
---

# SAML single sign-on

identity-service is the SAML service provider (SP). Each company can register one or more SAML identity providers (IdPs), such as Okta, Microsoft Entra ID, Google Workspace, or ADFS. Users sign in through the same `/api/v1/authorize` entry point as OAuth, and SAML accounts never link to existing users by email unless you set up verified domains.

## Set up an IdP

1. Check that `GET /api/v1/oauth-provider-catalog` lists the `saml` entry with `supported: true`.
2. Create the IdP with `POST /api/v1/oauth-social-apps`:
   - `docs_slug`: `saml`
   - `extra_settings`: the IdP fields, described by the catalog `extra_settings_schema`
3. Read `saml` in the `social_app` of the response:
   - `entity_id`: the SP entity ID to paste into the IdP
   - `acs_url`: the assertion consumer service (ACS) URL
   - `metadata_url`: the SP metadata XML, for IdPs that import it
4. In the IdP, map the `uid`, email, and optional name attributes to match your `attribute_mapping`.
5. Set `idp_entity_id` in identity-service to the IdP entity ID.

### Import IdP metadata

Instead of entering `sso_url` and `x509cert` by hand, set `metadata_url`. On save, identity-service fetches that URL with the same SSRF-protected HTTP client as OAuth discovery (512 KB maximum), stores the redirect SSO URL, and keeps a signing certificate (a `KeyDescriptor` with use `signing`, or with no use). An encryption-only certificate is rejected with `saml_metadata_missing_certificate`. Imported and manual `sso_url` and `slo_url` values must be public HTTPS URLs.

### Vendor guides

- [Okta SAML app setup](https://help.okta.com/oie/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm)
- [Microsoft Entra ID SAML SSO](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso)
- [Google Workspace custom SAML apps](https://support.google.com/a/answer/6087519)

## Sign in

Users start from the same browser entry point as OAuth:

```text
GET /api/v1/authorize?provider=saml&company_id=…&company_oauth_client_id=…&redirect_to=…
```

identity-service redirects the user to the IdP, which posts back to the company ACS URL. The rest of the flow (confirmation page, token delivery) is the same as [OAuth login](oauth-login.md).

The SP-initiated login URL `/api/v1/saml/organization_slug/login/` validates `redirect_to` the same way as `/api/v1/authorize`. `token_delivery` accepts `code` or `fragment` and ignores any other value; the default is `OAUTH_TOKEN_DELIVERY`.

### IdP-initiated sign-in

IdP-initiated sign-in is off by default (`allow_idp_initiated_sso: false`). Turn it on only after a risk review: an unsolicited response has no `InResponseTo` to bind it to a sign-in the user started.

### Logout

IdP-initiated logout at the SLS URL requires a signed logout request. When the NameID matches a SAML account for that IdP, identity-service revokes that user's refresh sessions in the IdP's company.

## Email linking

By default, a SAML sign-in creates or finds the user by SAML uid only. IdP attributes such as `email_verified` never turn on linking by email.

The only exception is when all of these hold:

1. The IdP has `trusted_for_verified_domains: true`.
2. The email domain of the assertion is in the company `verified_email_domains` (Shellui domain verification, not `allowed_email_domains`).
3. The email does not already belong to another user with a different SAML uid (`saml_email_conflict`).

### Domain verification

`verified_email_domains` is not writable through the company admin API, so company owners cannot claim a domain to unlock email linking. Shellui operators set it in Django admin after confirming domain ownership. Self-service verification with a DNS TXT record is planned.

## Security

identity-service keeps SAML accounts separate per company and always validates assertions strictly.

### Account isolation

Each SAML provider app belongs to one company, and cannot move to another company. SAML accounts are stored under `saml-{social_app_id}`, not the bare provider ID `saml`. The same IdP entity ID cannot be registered for two companies (`saml_idp_entity_id_in_use`).

Changing `client_id` (the organization slug) with a PUT fails with `oauth_app_client_id_taken` when another provider app already uses that value. A slug that matches more than one SAML app returns **404** `saml_app_not_found`.

### Assertion checks

| Check | Behavior |
| --- | --- |
| Strict mode and signed assertions | Always on. Admin `advanced` settings cannot turn them off |
| `InResponseTo` | Single use, bound to the browser session that started the sign-in |
| Replay | Assertion IDs are stored in the shared cache until the assertion `NotOnOrAfter` (15 minutes maximum). Production needs Redis, see [Shared cache (Redis)](configuration.md#shared-cache-redis) |
| Missing `Audience` | Rejected with `saml_audience_missing` |
| Transient NameID used as the account ID | Rejected with `saml_nameid_transient` |
| No email in the assertion | Rejected with `saml_email_required`. identity-service never invents an email |

ACS errors return JSON `{"error_code": "…"}`. A successful sign-in is recorded once, when the confirmation step completes or is skipped.

## Related

- [OAuth providers](oauth-providers.md): the SAML entry and the other providers
- [SCIM provisioning](scim.md): create users and groups from the same IdP
- [Company access](company-access.md): who may join a company after sign-in
