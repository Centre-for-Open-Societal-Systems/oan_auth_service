# eSignet login via OpenG2P IAM: implementation guide

Status: draft. Written from the `OpenG2P/iam` source and a read-only inspection of the
`openg2p-dev` cluster on 2026-10-26.

Items marked **VERIFY** were not confirmed against the running system or the upstream
docs. Do not run the SQL or API calls in this guide until you have checked them.

---

## 1. What you are building

OpenG2P IAM (`github.com/OpenG2P/iam`) treats every identity provider as a row in the
`login_providers` table. eSignet is not a separate integration. It is one provider row
with `adapter_name = esignet`, handled by `EsignetAdapter` on top of the generic OIDC
code in `iam-core`.

```
Browser -> Portal API (/auth/*) -> iam-core AuthService -> eSignet
              |                                              |
              |<---- /auth/callback?code=&state= <-----------|
              +--> sets X-Access-Token / X-ID-Token cookies
```

The flow is OAuth2 authorization code with PKCE, nonce and state. Authlib does the OIDC
work. IAM's own code is in `iam-core/src/iam_core/user_auth/` and `services/`.

### Who logs in with eSignet

- Keycloak is for staff and agents. The chart comments say the agent login is a plain
  Keycloak password login.
- eSignet is for beneficiaries and farmers, authenticated inside the registry's
  issuance flow. In the IAM repo that is the `iam-bene-portal-api` service.

---

## 2. Current state on openg2p-dev

| Item                   | State                                                                                                                 |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------- |
| eSignet service        | Running in `commons`: `commons-services-esignet`, `commons-services-esignet-oidc-ui`                                  |
| eSignet URL            | `https://esignet.development.oanstaging.com` (legacy host: `esignet-development.oanstaging.com`)                      |
| Keymanager             | Running in `commons`: `commons-services-keymanager`                                                                   |
| IAM database           | `iam` on `commons-postgresql`, table `login_providers`                                                                |
| Provider rows          | 2, both Keycloak: id 1 (`staff-portal`, staff realm), id 10 (`agent-portal`, agent realm)                             |
| eSignet provider row   | Does not exist                                                                                                        |
| eSignet OIDC clients   | `mosip_esignet.esignet.client_detail` has 0 rows                                                                      |
| Keymanager app for IAM | Does not exist. Existing app IDs: `ROOT`, `BASE`, `OPENG2P_SR`, `_SPAR`, `_PBMS`, `_BRIDGE` and their `_NID` variants |
| Beneficiary IAM API    | Not deployed. The cluster has `iam-agent-portal-api`, but no `iam-bene-portal-api`                                    |

### eSignet discovery document

From `https://esignet.development.oanstaging.com/v1/esignet/oidc/.well-known/openid-configuration`:

| Setting                               | Value                                                                                     |
| ------------------------------------- | ----------------------------------------------------------------------------------------- |
| issuer                                | `https://esignet.development.oanstaging.com`                                              |
| authorization_endpoint                | `https://esignet.development.oanstaging.com/authorize`                                    |
| token_endpoint                        | `https://esignet.development.oanstaging.com/v1/esignet/oauth/v2/token`                    |
| userinfo_endpoint                     | `https://esignet.development.oanstaging.com/v1/esignet/oidc/userinfo`                     |
| jwks_uri                              | `https://esignet.development.oanstaging.com/.well-known/jwks.json`                        |
| token_endpoint_auth_methods_supported | `private_key_jwt` only                                                                    |
| signing alg                           | RS256 (token endpoint auth, ID token and userinfo)                                        |
| claims_parameter_supported            | true                                                                                      |
| subject_types_supported               | `pairwise`                                                                                |
| claims_supported                      | name, address, gender, birthdate, picture, email, phone_number, individual_id             |
| acr_values_supported                  | `mosip:idp:acr:static-code`, `generated-code`, `linked-wallet`, `biometrics`, `knowledge` |

Constraints that follow from this:

1. A client secret cannot be used. The provider must use `private_key_jwt` or
   `private_key_jwt_keymanager`.
2. The `sub` is pairwise, so it differs per client. IAM's adapter identifies the person
   by `individual_id` and falls back to `sub`. Request `individual_id` explicitly.
3. `individual_id` is a claim, not a scope. Request it through the `claims` authorize
   parameter, not through `scope`.
4. The userinfo response is a signed JWT. The adapter validates it before merging.

---

## 3. How IAM handles eSignet (code reference)

### Adapter selection

`adapter_factory.py` maps `adapter_name` to an adapter. `esignet` and `mosip_esignet`
both map to `EsignetAdapter`. A null or empty `adapter_name` falls back to the generic
OIDC adapter, and none of the eSignet behaviour below applies.

### What `EsignetAdapter` adds

Source: `iam-core/src/iam_core/user_auth/adapters/implementations/esignet_adapter.py`.

- **Claims authorize param.** If `extra_authorize_params` contains a `claims` object, it
  is JSON-encoded to a compact string before URL-encoding. Store `claims` as a normal
  JSON object inside `extra_authorize_params`.
- **Userinfo merge.** After the token exchange the adapter calls userinfo and merges it
  over the ID token claims.
  - A userinfo `sub` that differs from the ID token `sub` raises a 401
    (OIDC Core 5.3.4).
  - A userinfo response that fails verification also raises a 401.
  - Any other userinfo failure is ignored and the ID token claims are used.
- **Subject.** `individual_id`, else `sub`. If both are missing, login fails with
  "Missing required subject claim".
- **Roles.** If there is no `roles` claim, it falls back to `realm_access.roles`.

### Client authentication

`iam-core/src/iam_core/user_auth/helpers/client_assertion_helper.py` builds the client
assertion:

- Claims: `iss` and `sub` are the `client_id`. `aud` is `jwt_assertion_aud`, or the
  `token_endpoint` when that is empty. `exp` is 1 hour.
- `private_key_jwt_keymanager`: signed by the MOSIP keymanager, using
  `keymanager_app_id` and `keymanager_ref_id`.
- `private_key_jwt`: signed locally with `client_private_key` (PEM, RS256 by default).

### Login provider fields

Defined in `iam-core/src/iam_core/models/login_provider.py`. Required: `id`,
`provider_name`, `client_id`, `token_endpoint_auth_method`, `issuer`,
`oauth_callback_url`. Either `server_metadata_url`, or the individual endpoints, must be
present.

### Sources of provider rows

The staff and agent portal charts render provider rows from Helm values into a secret
(`login-providers-secret.yaml`). That template hardcodes `adapter_name` to empty, builds
every endpoint from a Keycloak realm URL, and has no `claims` parameter. It cannot
produce an eSignet row. Either insert the row into the database (section 6), or extend
the chart (section 7).

---

## 4. Implementation plan

Do the steps in order. Each depends on the previous one.

### Step 0: decide the target

Decide:

- Which portal API will use eSignet. Assumption in this guide: a beneficiary or farmer
  portal API based on `iam-bene-portal-api`.
- Its public hostname. The callback URL is `https://<bene-iam-host>/auth/callback`.
  Example host: `bene-iam.development.oanstaging.com`. **VERIFY** the naming convention.
- Which `acr_values` and which claims the registry needs.
- Which `user_type` the rows use. The chart's `loginProviders` values carry a `userType`,
  and the portal APIs filter providers by user type. **VERIFY** the value for beneficiary
  in the `iam` code.

### Step 1: deploy the beneficiary IAM API

The upstream chart has templates for `iam-staff-portal-api`, `iam-agent-portal-api` and
`iam-staff-ui`. There is no template for `iam-bene-portal-api`, although a Dockerfile
exists at `docker/iam-bene-portal-api/Dockerfile`. You will need to:

1. Build and publish the image from that Dockerfile, or confirm one exists.
2. Create a chart template modelled on `iam-agent-portal-api`: deployment, service,
   virtual service, gateway and secret.
3. Share the IAM database and Redis (auth transaction and refresh token stores) with the
   other IAM APIs. The agent chart already does this.
4. Set the cookie name prefix and cookie domain so the bene cookies do not collide with
   staff or agent cookies. See `tests/test_cookie_name_prefix.py` for the supported
   setting. **VERIFY**.

### Step 2: create a keymanager application and key for IAM

The assertion must be signed by a key that eSignet trusts. With
`private_key_jwt_keymanager`, that key lives in the MOSIP keymanager.

1. Add a key policy for a new app ID, for example `OPENG2P_IAM`, in
   `mosip_keymgr.keymgr.key_policy_def`. Existing apps use a validity of 1095 days.
2. Generate the key pair for that app ID (and an optional `ref_id`).
3. Export the certificate or public key and convert it to a JWK for step 3.

The existing `OPENG2P_*` apps were all created at the same time, on 2026-10-12, and
probably come from a deployment job or chart values. Look at how that was done (search
the `commons-services-keymanager` deployment and its init job) and add `OPENG2P_IAM` the
same way, instead of inserting rows by hand. **VERIFY** the mechanism.

Upstream keymanager endpoints that are normally involved (**VERIFY** against your
deployed version): `/v1/keymanager/generateMasterKey/{objectType}` to create the key and
`/v1/keymanager/getCertificate` to read the certificate.

### Step 3: register the OIDC client in eSignet

`mosip_esignet.esignet.client_detail` columns:

| Column          | Value                                                                               |
| --------------- | ----------------------------------------------------------------------------------- |
| `id`            | The client id, for example `iam-bene-portal`. Must equal the provider's `client_id` |
| `name`          | Display name                                                                        |
| `rp_id`         | Relying party id                                                                    |
| `logo_uri`      | Required, not null                                                                  |
| `redirect_uris` | JSON array containing the IAM callback URL exactly                                  |
| `claims`        | JSON array of claims this client may request, including `individual_id`             |
| `acr_values`    | JSON array of allowed acr values                                                    |
| `public_key`    | JWK of the public key from step 2                                                   |
| `grant_types`   | `["authorization_code"]`                                                            |
| `auth_methods`  | `["private_key_jwt"]`                                                               |
| `status`        | `ACTIVE`                                                                            |

Prefer eSignet's own client management API over a direct insert. The upstream path is
`/v1/esignet/client-mgmt/oidc-client`, which needs an authorized call. **VERIFY** the
path and auth for your eSignet version. If you must insert directly in dev, copy the
exact JSON formats from the eSignet client-management documentation, because the column
formats are easy to get wrong.

### Step 4: add the IAM login provider row

Draft SQL for the `iam` database. Replace every `TODO` value. Do not run it before steps
2 and 3 are done and the column list is checked against `\d login_providers`:

```sql
INSERT INTO login_providers (
  id, provider_name, description, client_id, token_endpoint_auth_method,
  keymanager_app_id, keymanager_ref_id,
  authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
  server_metadata_url, adapter_name, jwt_assertion_aud,
  scope, enable_pkce, extra_authorize_params,
  issuer, audiences, oauth_callback_url, default_redirect_uri,
  created_at, updated_at
) VALUES (
  /* id */                  TODO_NEXT_FREE_ID,
  'e-Signet',
  'Sign in with e-Signet',
  /* client_id */           'iam-bene-portal',                           -- TODO match client_detail.id
  'private_key_jwt_keymanager',
  /* keymanager_app_id */   'OPENG2P_IAM',                               -- TODO from step 2
  /* keymanager_ref_id */   '',
  'https://esignet.development.oanstaging.com/authorize',
  'https://esignet.development.oanstaging.com/v1/esignet/oauth/v2/token',
  'https://esignet.development.oanstaging.com/v1/esignet/oidc/userinfo',
  'https://esignet.development.oanstaging.com/.well-known/jwks.json',
  'https://esignet.development.oanstaging.com/v1/esignet/oidc/.well-known/openid-configuration',
  'esignet',
  NULL,                                                                  -- uses token endpoint as aud
  'openid profile',
  true,
  '{"claims":{"userinfo":{"individual_id":{"essential":true},"name":{"essential":false}},"id_token":{}},"acr_values":"mosip:idp:acr:generated-code mosip:idp:acr:biometrics"}',
  'https://esignet.development.oanstaging.com',
  '',
  'https://TODO-bene-iam-host/auth/callback',
  'https://TODO-bene-portal-host',
  now(), now()
);
```

Check before running:

- `\d login_providers` on the live database. The chart template also writes `user_type`
  and `active`, which may be database columns the Python model above does not list.
  Match what the table actually has.
- Existing rows store the unused `jwt_assertion_aud` and `extra_authorize_params` as the
  string `NULL`, not SQL NULL (see the chart template). Use the same convention if the
  code expects it. **VERIFY** how the code treats an empty value.
- Does `token_endpoint_auth_method` accept the enum value `private_key_jwt_keymanager`?
  It is in `TokenEndpointAuthMethod`.
- Is `acr_values` an `extra_authorize_params` key, or does the base class send it? Look
  at `oidc_base.py` `build_authorize_redirect`. **VERIFY**.
- Sort out `audiences`. If the portal API validates access tokens, the issuer and
  audience must match what eSignet issues.

### Step 5: wire the frontend

The frontend calls, in order:

1. `GET /auth/get_login_providers` to list providers, then show an e-Signet button.
2. `POST /auth/start_authentication_transaction?id=<provider_id>&redirect_uri=<return>`.
   The response is `{redirectUrl, state}`. Redirect the browser to `redirectUrl`.
3. After eSignet redirects to `/auth/callback`, the API sets cookies and redirects to
   `redirect_uri`. The frontend then calls `GET /auth/get_user_profile` with credentials.

Cookies are host cookies with no `domain`, so they only reach the portal API's own
host. Cross-host SSO needs a cookie domain setting or a bearer-token approach. See
`docs/staff-portal-sso-login-flow.md` in the IAM repo.

---

## 5. Verification checklist

Run each check in order and stop at the first failure.

1. **Discovery.** `curl` the discovery URL from inside the cluster and from outside.
2. **Provider list.** `GET /auth/get_login_providers` on the bene API returns the
   e-Signet row.
3. **Start transaction.** The returned `redirectUrl` contains `client_id`,
   `code_challenge`, `nonce`, `state`, `scope` and a `claims` parameter that is a
   URL-encoded JSON string.
4. **eSignet accepts the request.** The eSignet UI loads. An invalid client id or
   redirect URI shows an error here, which means step 3 is wrong.
5. **Token exchange.** `/auth/callback` completes with no 401 or 500 in the portal API
   logs. A failure here usually means the assertion key does not match the registered
   public key.
6. **Claims.** `GET /auth/get_user_profile` shows the subject. Check that
   `individual_id` was present. For a mismatch error see the troubleshooting table.
7. **Logout.** `POST /auth/logout` clears the cookies and the refresh token.

---

## 6. Troubleshooting

| Symptom                                            | Likely cause                                                                                                        |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| eSignet shows an invalid client or redirect error  | `client_detail.id` or `redirect_uris` does not match `client_id` or `oauth_callback_url`                            |
| Token endpoint returns `invalid_client`            | Assertion signed with a key that does not match `client_detail.public_key`, wrong `aud`, or wrong `client_id`       |
| "Userinfo subject does not match the ID token"     | eSignet returned a different `sub` in userinfo. The adapter refuses to merge. Check the client and eSignet versions |
| "Missing required subject claim"                   | `individual_id` was not requested or not allowed in `client_detail.claims`                                          |
| "Unauthorized. Unknown Issuer"                     | Provider row `issuer` is not exactly what eSignet issues                                                            |
| "Unauthorized. Unknown Audience"                   | `audiences` does not match the token audience                                                                       |
| "Nonce mismatch"                                   | The Redis transaction store lost the state, or the callback was replayed                                            |
| Login works but cookies are missing on other hosts | Cookies are host-only. See step 5                                                                                   |
| Adapter behaviour absent (no claims encoding)      | `adapter_name` is empty, so the generic adapter was used                                                            |

---

## 7. Optional: chart changes instead of manual SQL

If provider rows must come from Helm, extend
`templates/iam-staff-portal-api/login-providers-secret.yaml` (or the new bene template)
so a provider can set explicit endpoints and an adapter. Needed per provider:

- `adapterName`
- full endpoint URLs, or `serverMetadataUrl`, instead of deriving from a Keycloak realm
- `jwtAssertionAud`, `keymanagerAppId`, `keymanagerRefId`
- `extraAuthorizeParams` (rendered as a JSON string)
- `issuer` and `audiences`
- the `private_key_jwt_keymanager` auth method

This needs a contribution to `OpenG2P/iam`, or a patch in your fork.

---

## 8. Open items

1. Decide which portal and hostname will use eSignet.
2. Find out how the `OPENG2P_*` keymanager apps were provisioned and use the same path
   for `OPENG2P_IAM`.
3. Confirm the eSignet client registration route and its authorization.
4. Confirm the `login_providers` column list on the live database (it differs between
   the chart template and the Python model) and the `user_type` value for beneficiaries.
5. Build, publish and deploy `iam-bene-portal-api`.
6. Decide the acr values and claims the registry needs.
7. Decide how production eSignet clients will be registered, since this guide is dev
   only.
