# OAN Authentication Service — API Reference & Documentation

Comprehensive API documentation for the **OAN Authentication Service** (`oan_auth_service`), detailing all endpoints, authentication schemes, request parameters, JSON bodies, and response envelopes.

---

## Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Base URLs & Transport](#base-urls--transport)
- [Authentication Scheme](#authentication-scheme)
- [Standard Response Formats](#standard-response-formats)
  - [Success Envelope](#success-envelope)
  - [Error Envelope](#error-envelope)
- [Endpoints Summary](#endpoints-summary)
- [Authentication & Session Endpoints](#authentication--session-endpoints)
  - [1. User Registration (`POST /api/v1/auth/register`)](#1-user-registration-post-apiv1authregister)
  - [2. User Login (`POST /api/v1/auth/login`)](#2-user-login-post-apiv1authlogin)
  - [3. Token Refresh (`POST /api/v1/auth/refresh`)](#3-token-refresh-post-apiv1authrefresh)
  - [4. User Logout (`POST /api/v1/auth/logout`)](#4-user-logout-post-apiv1authlogout)
- [Password Recovery Endpoints](#password-recovery-endpoints)
  - [5. Forgot Password (`POST /api/v1/auth/forgot-password`)](#5-forgot-password-post-apiv1authforgot-password)
  - [6. Reset Password (`POST /api/v1/auth/reset-password`)](#6-reset-password-post-apiv1authreset-password)
- [Temporary Password Endpoints](#temporary-password-endpoints)
  - [11. Set Initial Password (`POST /api/v1/auth/set-initial-password`)](#11-set-initial-password-post-apiv1authset-initial-password)
  - [12. Issue Temporary Password (`POST /api/v1/auth/temporary-password`)](#12-issue-temporary-password-post-apiv1authtemporary-password)
- [Identity & Profile Endpoints](#identity--profile-endpoints)
  - [7. Introspect User (`GET /api/v1/auth/me`)](#7-introspect-user-get-apiv1authme)
- [System & Discovery Endpoints](#system--discovery-endpoints)
  - [8. Key Metadata Discovery (`GET /api/v1/auth/keys`)](#8-key-metadata-discovery-get-apiv1authkeys)
  - [9. Health Check (`GET /api/v1/auth/health`)](#9-health-check-get-apiv1authhealth)
  - [10. Public Metadata (`GET /api/v1/auth/metadata`)](#10-public-metadata-get-apiv1authmetadata)

---

## Overview & Architecture

`oan_auth_service` provides unified JWT authentication, user lifecycle management, and session control for the OpenAgriNet ecosystem.

### Token Architecture

- **Access Token (JWT)**:
  - Signed using `RS256` with a rotating Key ID (`kid`). Verify with the public keys from `GET /api/v1/auth/keys`.
  - Self-contained claims (`sub`, `roles`, `iss`, `iat`, `exp`, `jti`, optional `scope`).
  - Validated statelessly with zero database I/O.
  - Short-lived: **15 minutes** (900 seconds) by default.
- **Refresh Token (Opaque String)**:
  - 32 bytes of cryptographically secure random bytes (`secrets.token_urlsafe(32)`).
  - Stored exclusively as a SHA-256 hash in the database (`OAN User Refresh Token`).
  - **Single-use & Rotated**: The database entry is unconditionally consumed upon exchange to prevent replay attacks.
  - Standard TTL: **30 days** (`DEFAULT_REFRESH_TOKEN_TTL`).
  - Remember Me TTL: **90 days** (`DEFAULT_REFRESH_TOKEN_TTL_REMEMBER_ME`).

---

## Base URLs & Transport

| Environment                 | Base URL                       |
| :-------------------------- | :----------------------------- |
| **Local Development**       | `http://localhost:8000`        |
| **Production Auth Gateway** | `https://auth.openagrinet.org` |

### RPC Alias Support

In addition to clean REST paths, all endpoints are whitelisted and accessible via standard Frappe RPC method syntax:

```http
POST /api/method/oan_auth_service.api.v1.auth.<function_name>
```

### Standard Request Headers

| Header          | Required            | Value / Description                                                                  |
| :-------------- | :------------------ | :----------------------------------------------------------------------------------- |
| `Content-Type`  | Required for `POST` | `application/json`                                                                   |
| `Accept`        | Optional            | `application/json`                                                                   |
| `Authorization` | Protected routes    | `Bearer <access_token>`                                                              |
| `X-Request-Id`  | Optional            | Client correlation ID (UUIDv4). If omitted, the service generates one automatically. |

---

## Standard Response Formats

All API responses are wrapped in standardized JSON envelopes.

### Success Envelope

HTTP Status: `200 OK`

```json
{
  "status": "success",
  "message": "Action completed successfully",
  "data": { ... },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
}
```

| Field        | Type               | Description                                                                      |
| :----------- | :----------------- | :------------------------------------------------------------------------------- |
| `status`     | `string`           | Always `"success"`.                                                              |
| `message`    | `string` \| `null` | Contextual confirmation message.                                                 |
| `data`       | `object` \| `null` | Endpoint-specific response payload.                                              |
| `meta`       | `object`           | Service metadata (`api_version`, `status`).                                      |
| `request_id` | `string`           | Tracing UUID for debugging and log correlation.                                  |
| `pagination` | `object` \| `null` | Optional pagination details (`page`, `page_size`, `total_pages`, `total_count`). |

### Error Envelope

HTTP Status: `400`, `401`, `403`, `404`, `429`, or `500`

```json
{
  "status": "error",
  "message": "Validation failed for one or more fields",
  "code": "VALIDATION_ERROR",
  "details": {},
  "errors": [
    {
      "field": "password",
      "message": "Password must contain at least one special character."
    }
  ],
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "c1f73b64-8bf2-4148-9336-d8bb30db15d9"
}
```

| Field        | Type                      | Description                                                                                           |
| :----------- | :------------------------ | :---------------------------------------------------------------------------------------------------- |
| `status`     | `string`                  | Always `"error"`.                                                                                     |
| `message`    | `string`                  | Human-readable error description.                                                                     |
| `code`       | `string`                  | Machine-readable error code (e.g. `AUTHENTICATION_ERROR`, `VALIDATION_ERROR`, `RATE_LIMIT_EXCEEDED`). |
| `details`    | `object`                  | Additional error context.                                                                             |
| `errors`     | `array[object]` \| `null` | Specific field-level validation errors (if applicable).                                               |
| `meta`       | `object`                  | Service metadata.                                                                                     |
| `request_id` | `string`                  | Tracing UUID.                                                                                         |

---

## Endpoints Summary

| Method | Path                                | Summary                                                | Auth Required    | Rate Limited            |
| :----- | :---------------------------------- | :----------------------------------------------------- | :--------------- | :---------------------- |
| `POST` | `/api/v1/auth/register`             | Register new user account                              | Public / Guest   | Yes (Caller IP)         |
| `POST` | `/api/v1/auth/login`                | Authenticate & obtain token pair                       | Public / Guest   | Constant-time flow      |
| `POST` | `/api/v1/auth/refresh`              | Exchange single-use refresh token                      | Public / Guest   | Single-use rotation     |
| `POST` | `/api/v1/auth/logout`               | Revoke active refresh token                            | Public / Guest   | No                      |
| `POST` | `/api/v1/auth/forgot-password`      | Initiate password recovery (SMS / Email)               | Public / Guest   | 10 req / hour / IP      |
| `POST` | `/api/v1/auth/reset-password`       | Complete password reset (Email Key or SMS OTP)         | Public / Guest   | 20 OTP req / hour / IP  |
| `POST` | `/api/v1/auth/set-initial-password` | Replace a temporary password                           | Public / Guest   | 10 req / 5 min / IP     |
| `POST` | `/api/v1/auth/temporary-password`   | Issue or reissue a temporary password (System Manager) | `Bearer <token>` | 10 req / 5 min / caller |
| `GET`  | `/api/v1/auth/me`                   | Current user profile & claims introspection            | `Bearer <token>` | No                      |
| `GET`  | `/api/v1/auth/keys`                 | JWT signing key ID & algorithm metadata                | Public / Guest   | No                      |
| `GET`  | `/api/v1/auth/health`               | Health check endpoint                                  | Public / Guest   | No                      |
| `GET`  | `/api/v1/auth/metadata`             | Aggregated app metadata & public roles                 | Public / Guest   | No                      |

---

## Authentication & Session Endpoints

### 1. User Registration (`POST /api/v1/auth/register`)

Registers a new user, creates canonical `User` and `Contact` records, triggers `on_user_registered` hooks across installed apps to link domain entities, and returns an initial access/refresh token pair.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/register`
- **Authorization**: Public / Guest
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field          | Type                        | Required   | Constraints             | Description                                                                                                                    |
| :------------- | :-------------------------- | :--------- | :---------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| `full_name`    | `string`                    | **Yes**    | 1 – 140 chars           | Full name of user or organization.                                                                                             |
| `password`     | `string`                    | **Yes**    | 8 – 128 chars           | Account password. Must meet complexity: at least 1 letter, 1 number, and 1 special character.                                  |
| `email`        | `string`                    | Optional\* | Valid email format      | User login email. (\*Note: At least one of `email` or `phone_number` must be provided).                                        |
| `phone_number` | `string`                    | Optional\* | E.164 / National number | Phone number. Full international E.164 string (e.g. `+251911223344`) or national subscriber digits when `country_code` is set. |
| `country_code` | `string`                    | Optional   | `+` and 1 – 4 digits    | Optional country calling code prefix (e.g. `+251`, `+91`). When provided, `phone_number` is treated as national digits.        |
| `role`         | `string`                    | Optional   | Valid role name         | Single role to request. Must be in `jwt_self_registerable_roles` configuration for guest callers.                              |
| `roles`        | `array[string]` \| `string` | Optional   | Valid role names        | List of roles to request. Must be in `jwt_self_registerable_roles`.                                                            |
| `...kwargs`    | `any`                       | Optional   | —                       | Extra arbitrary domain fields passed through to installed app `on_user_registered` hooks.                                      |

#### Request Body Examples

**Example A: Complete E.164 `phone_number`**

```json
{
  "full_name": "Abebe Bikila",
  "email": "abebe@example.com",
  "phone_number": "+251911223344",
  "password": "SecurePassword123!",
  "role": "Farmer",
  "district": "Arsi"
}
```

**Example B: Split `country_code` and `phone_number`**

```json
{
  "full_name": "Abebe Bikila",
  "email": "abebe@example.com",
  "country_code": "+251",
  "phone_number": "911223344",
  "password": "SecurePassword123!",
  "role": "Farmer",
  "district": "Arsi"
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "User registered successfully",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsImtpZCI6...",
    "refresh_token": "dGhpcyBpcyBhIHJhbmRvbSBzZWN1cmUgdG9rZW4...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": "USR-00001",
    "roles": ["Farmer"],
    "scope": null
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "a2430043-3929-47a2-a89e-26f634bc3d63"
}
```

---

### 2. User Login (`POST /api/v1/auth/login`)

Authenticates user credentials against Frappe's user store and returns a signed JWT access token and single-use refresh token.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/login`
- **Authorization**: Public / Guest
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field         | Type                        | Required | Default | Description                                                                        |
| :------------ | :-------------------------- | :------- | :------ | :--------------------------------------------------------------------------------- |
| `usr`         | `string`                    | **Yes**  | —       | Login identifier. Accepts **Email**, **Mobile Number**, or internal **User ID**.   |
| `pwd`         | `string`                    | **Yes**  | —       | Account password.                                                                  |
| `remember_me` | `boolean`                   | Optional | `false` | When `true`, extends the refresh token lifetime from **30 days** to **90 days**.   |
| `scope`       | `string` \| `array[string]` | Optional | `null`  | Optional list of roles to narrow down the token claims (cannot widen permissions). |

#### Request Body Example

```json
{
  "usr": "abebe@example.com",
  "pwd": "SecurePassword123!",
  "remember_me": true,
  "scope": ["Farmer"]
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsImtpZCI6...",
    "refresh_token": "4xO3G2u7V...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": "USR-00001",
    "roles": ["Farmer"],
    "scope": ["Farmer"]
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "761611d2-0692-4f93-b68e-7e9dc2a11b62"
}
```

---

### 3. Token Refresh (`POST /api/v1/auth/refresh`)

Exchanges an active refresh token for a newly minted access token and rotated refresh token. The submitted refresh token is permanently deleted before verification to prevent replay attacks.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/refresh`
- **Authorization**: Public / Guest
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field           | Type     | Required | Description                             |
| :-------------- | :------- | :------- | :-------------------------------------- |
| `refresh_token` | `string` | **Yes**  | Active, unexpired refresh token string. |

#### Request Body Example

```json
{
  "refresh_token": "4xO3G2u7VbZqI7Q_8jklM..."
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsImtpZCI6...",
    "refresh_token": "8mP9L2x1...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": "USR-00001",
    "roles": ["Farmer"],
    "scope": null
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "bfd7ce53-6ec7-42d4-bb39-b9fa9ebfae85"
}
```

---

### 4. User Logout (`POST /api/v1/auth/logout`)

Revokes the specified refresh token in the database, terminating the persistent session.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/logout`
- **Authorization**: Public / Guest
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field           | Type     | Required | Description                  |
| :-------------- | :------- | :------- | :--------------------------- |
| `refresh_token` | `string` | **Yes**  | The refresh token to revoke. |

#### Request Body Example

```json
{
  "refresh_token": "8mP9L2x1..."
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Token successfully revoked.",
  "data": {
    "revoked": true
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "426d4001-c88f-4ba9-8d76-c56baefb3c10"
}
```

---

## Password Recovery Endpoints

### 5. Forgot Password (`POST /api/v1/auth/forgot-password`)

Initiates account password recovery. The server intelligently determines the delivery channel based on the user record:

- If the account has an email: sends a **password reset link via email**.
- If the account is phone-only: dispatches a **6-digit numeric OTP via SMS**.

To prevent account enumeration, the response status and message are identical whether the account exists or not.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/forgot-password`
- **Authorization**: Public / Guest
- **Rate Limit**: 10 requests / hour / IP
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field | Type     | Required | Description                                             |
| :---- | :------- | :------- | :------------------------------------------------------ |
| `usr` | `string` | **Yes**  | Login handle: email address, mobile number, or User ID. |

#### Request Body Example

```json
{
  "usr": "abebe@example.com"
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "If that account exists, reset instructions have been sent.",
  "data": null,
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "060d4013-1cfd-4da7-be70-66c30f40d6c1"
}
```

---

### 6. Reset Password (`POST /api/v1/auth/reset-password`)

Completes password reset using either verification method. Upon successful password reset, **all existing refresh tokens for the user are immediately revoked** to safeguard against compromised sessions.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/reset-password`
- **Authorization**: Public / Guest
- **Rate Limit**: 20 attempts / hour / IP (on SMS OTP flow)
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

Must provide **either** `key` (Email flow) **OR** (`usr` + `otp`) (SMS flow), but **not both**.

| Field          | Type     | Required    | Constraints   | Description                                                                               |
| :------------- | :------- | :---------- | :------------ | :---------------------------------------------------------------------------------------- |
| `new_password` | `string` | **Yes**     | 8 – 128 chars | New password. Must meet complexity: at least 1 letter, 1 number, and 1 special character. |
| `key`          | `string` | Conditional | Email Flow    | The reset token key received from the email link.                                         |
| `usr`          | `string` | Conditional | SMS Flow      | Login handle (email or phone number).                                                     |
| `otp`          | `string` | Conditional | SMS Flow      | Numeric one-time password received via SMS. Valid for 10 minutes (max 5 attempts).        |

#### Request Body Examples

**Variant A: Email Reset Link (`key`)**

```json
{
  "key": "c356f671c699fa2e4ba7dbd5...",
  "new_password": "NewStrongPassword123#"
}
```

**Variant B: SMS OTP (`usr` + `otp`)**

```json
{
  "usr": "+251911223344",
  "otp": "492015",
  "new_password": "NewStrongPassword123#"
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Password updated successfully",
  "data": null,
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "db0a8ee6-05ec-4be4-af39-8134aeaf4a69"
}
```

---

## Temporary Password Endpoints

An admin can give an account a **temporary password**: one somebody other than the account holder chose. The account can authenticate with it, but cannot open a session. Until the holder replaces it:

- `POST /api/v1/auth/login` answers **403** with `code: "PASSWORD_CHANGE_REQUIRED"` when the password is right (a wrong password is still a plain 401).
- `POST /api/v1/auth/refresh` refuses refresh tokens and access tokens already issued to the account stop working.
- Issuing a temporary password ends every session the account already held.

The holder replaces it with `POST /api/v1/auth/set-initial-password`. Apps that create accounts for others (for example officers) call `issue_temporary_password(user, password)` from `oan_auth_service.api.v1.auth` after checking that their caller may manage that account.

### 11. Set Initial Password (`POST /api/v1/auth/set-initial-password`)

Replaces a temporary password with one only the account holder knows. No token is needed or issued: the temporary password is the proof. Sign in with the new password afterwards.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/set-initial-password`
- **Authorization**: Public / Guest
- **Rate Limit**: 10 requests / 5 minutes / IP. Wrong passwords also count towards the account lockout, as at login.
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field              | Type     | Required | Constraints   | Description                                                                              |
| :----------------- | :------- | :------- | :------------ | :--------------------------------------------------------------------------------------- |
| `usr`              | `string` | **Yes**  | Min 1 char    | Login handle (email, phone number or user id).                                           |
| `current_password` | `string` | **Yes**  | Min 1 char    | The temporary password.                                                                  |
| `new_password`     | `string` | **Yes**  | 8 – 128 chars | At least 1 letter, 1 number and 1 special character. Must differ from the temporary one. |

#### Request Body Example

```json
{
  "usr": "tigist.alemu@example.com",
  "current_password": "Welcome2026",
  "new_password": "MyOwn#Password1"
}
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Password set. Please sign in with your new password.",
  "data": null,
  "meta": { "api_version": "v1", "status": "current" },
  "request_id": "db0a8ee6-05ec-4be4-af39-8134aeaf4a69"
}
```

An unknown account, a wrong password and an account that holds no temporary password all return the same `401 AUTHENTICATION_ERROR` "Invalid login credentials", so the endpoint reveals neither which accounts exist nor which hold a temporary password.

---

### 12. Issue Temporary Password (`POST /api/v1/auth/temporary-password`)

Sets a temporary password on any account, for a first password or after a forgotten one. **System Manager only**, because the caller chooses the password and could otherwise take over any account. A role that should reach only its own users belongs in the consuming app, which checks its target and calls `issue_temporary_password`.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/auth/temporary-password`
- **Authorization**: Required (`Bearer <access_token>`), System Manager
- **Rate Limit**: 10 requests / 5 minutes / caller
- **Header**: `Content-Type: application/json`

#### Request Body Parameters

| Field      | Type     | Required | Constraints   | Description                                                           |
| :--------- | :------- | :------- | :------------ | :-------------------------------------------------------------------- |
| `usr`      | `string` | **Yes**  | Min 1 char    | Login handle of the account. `Administrator` and `Guest` are refused. |
| `password` | `string` | **Yes**  | 8 – 128 chars | At least 1 letter and 1 number. A special character is not required.  |

#### Request Body Example

```json
{ "usr": "tigist.alemu@example.com", "password": "Welcome2026" }
```

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Temporary password issued. The account holder must set their own password before signing in.",
  "data": null,
  "meta": { "api_version": "v1", "status": "current" },
  "request_id": "db0a8ee6-05ec-4be4-af39-8134aeaf4a69"
}
```

Errors: `403 PERMISSION_DENIED` for a caller who is not a System Manager or for a protected account, `404 NOT_FOUND` for an unknown account, `400 VALIDATION_ERROR` for a weak password.

---

## Identity & Profile Endpoints

### 7. Introspect User (`GET /api/v1/auth/me`)

Returns the profile, identity attributes, and assigned roles of the currently authenticated user. Additionally collects and returns app-specific profiles via the `on_user_profile` hook.

- **HTTP Method**: `GET`
- **Path**: `/api/v1/auth/me`
- **Authorization**: Required (`Bearer <access_token>`)
- **Headers**:
  - `Authorization: Bearer <access_token>`

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Success",
  "data": {
    "user": "USR-00001",
    "first_name": "Abebe",
    "last_name": "Bikila",
    "full_name": "Abebe Bikila",
    "login_email": "abebe@example.com",
    "mobile_no": "+251911223344",
    "country_code": "+251",
    "phone_number": "911223344",
    "roles": ["Farmer"],
    "profiles": {
      "grievance": {
        "farmer_id": "FRM-00812",
        "cooperative": "Arsi Union"
      }
    }
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "1e72e0bf-52d3-4601-bd31-923cb8c8efd4"
}
```

#### Response Fields (`data`)

| Field          | Type               | Description                                                                  |
| :------------- | :----------------- | :--------------------------------------------------------------------------- |
| `user`         | `string`           | Unique User ID / internal handle.                                            |
| `first_name`   | `string` \| `null` | First name.                                                                  |
| `last_name`    | `string` \| `null` | Last name.                                                                   |
| `full_name`    | `string`           | Display name.                                                                |
| `login_email`  | `string` \| `null` | Authoritative login email address.                                           |
| `mobile_no`    | `string` \| `null` | Complete international mobile number (E.164 format).                         |
| `country_code` | `string` \| `null` | Extracted country calling code (e.g. `+251`).                                |
| `phone_number` | `string` \| `null` | Extracted national subscriber phone number (e.g. `911223344`).               |
| `roles`        | `array[string]`    | Active roles assigned to the user.                                           |
| `profiles`     | `object`           | Namespaced domain profiles supplied by installed apps via `on_user_profile`. |

---

## System & Discovery Endpoints

### 8. Key Metadata Discovery (`GET /api/v1/auth/keys`)

Returns the RS256 public keys (as JWKs) that verify access tokens, the kid currently used for signing, and the issuer identity. Every kid still accepted for verification is listed, not only the active one, so a verifier that caches this response can still check tokens minted before a rotation. Match a token to its key by the `kid` in the token header. Private key material is never exposed.

- **HTTP Method**: `GET`
- **Path**: `/api/v1/auth/keys`
- **Authorization**: Public / Guest

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Success",
  "data": {
    "issuer": "oan-auth",
    "algorithm": "RS256",
    "active_kid": "prod-key-2026a",
    "keys": [
      {
        "kid": "prod-key-2026a",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4...",
        "e": "AQAB"
      }
    ]
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "4527d928-8685-48ef-b633-85f269a843aa"
}
```

---

### 9. Health Check (`GET /api/v1/auth/health`)

Lightweight health status check for load balancers, container orchestrators, and uptime monitors.

- **HTTP Method**: `GET`
- **Path**: `/api/v1/auth/health`
- **Authorization**: Public / Guest

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Success",
  "data": {
    "status": "healthy",
    "service": "oan_auth_service",
    "api_version": "v1"
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "2d8f99bc-3023-4fa8-8fa1-71ecadbc4b12"
}
```

---

### 10. Public Metadata (`GET /api/v1/auth/metadata`)

Aggregates public reference metadata, registration parameters, and domain metadata registered via `on_metadata` hooks across installed apps.

- **HTTP Method**: `GET`
- **Path**: `/api/v1/auth/metadata`
- **Authorization**: Public / Guest

#### Response: `200 OK`

```json
{
  "status": "success",
  "message": "Metadata retrieved successfully",
  "data": {
    "auth": {
      "self_registerable_roles": ["Farmer", "Customer"]
    },
    "grievance": {
      "categories": ["Crop Damage", "Payment Delay", "Input Shortage"]
    }
  },
  "meta": {
    "api_version": "v1",
    "status": "current"
  },
  "request_id": "c1f73b64-8bf2-4148-9336-d8bb30db15d9"
}
```

---

## Common Error Codes Reference

| HTTP Status             | Error Code (`code`)        | Trigger Reason                                                                                            |
| :---------------------- | :------------------------- | :-------------------------------------------------------------------------------------------------------- |
| `400 Bad Request`       | `VALIDATION_ERROR`         | Malformed JSON, missing mandatory fields, invalid phone/email, or failed password complexity.             |
| `401 Unauthorized`      | `AUTHENTICATION_ERROR`     | Invalid credentials, expired/replayed refresh token, or invalid/expired password reset code.              |
| `403 Forbidden`         | `PERMISSION_ERROR`         | Requesting a role not permitted for public self-registration.                                             |
| `403 Forbidden`         | `PASSWORD_CHANGE_REQUIRED` | Correct credentials, but the account holds a temporary password. Send the user to `set-initial-password`. |
| `403 Forbidden`         | `HTTPS_REQUIRED`           | Request made over plain HTTP when `jwt_enforce_https` is enabled.                                         |
| `429 Too Many Requests` | `RATE_LIMIT_EXCEEDED`      | Exceeded rate limit on forgot-password or OTP verification endpoints.                                     |
| `500 Server Error`      | `INTERNAL_SERVER_ERROR`    | Unhandled runtime exception or key configuration error.                                                   |
