# Admin API rules

Business rules for `/api/v1/admin` (public `/v1/admin`). Code: `oan_auth_service/api/v1/admin.py`.

## Who can call it

Every endpoint requires System Manager or Administrator. Frappe's own `/api/resource/User` is not a substitute: it does not accept this service's bearer tokens, and it knows nothing of the synthetic user id, the login email field, the linked Contact or the `on_user_registered` hook.

## Service scope

Only roles, doctypes and users of the calling service are visible.

- A role or doctype is in scope when its name starts with a configured prefix. A user is in scope when they hold at least one such role.
- A dependent app declares its prefix with the `oan_service_prefix` hook in `hooks.py`, for example `oan_service_prefix = "A2C"`. The `service_prefix` site config key (a string or a list) takes precedence. With neither, scoped endpoints answer 400.
- An out-of-scope user answers 404. Granting a role outside the prefix answers 400; removing one answers 403. The admin API therefore cannot grant `System Manager` or `Administrator`.
- A new user needs at least one in-scope role, or they would be invisible right after creation.

## Protected accounts

- Nobody can disable the `Administrator` account or their own account, or change their own roles or password through this API.
- Only the `Administrator` user may change the contact details, password, roles or sessions of `Administrator` or of any holder of the Administrator role. Otherwise a System Manager could change that account's email or phone, run forgot-password and sign in as it. A System Manager may manage other System Managers.
- Only the `Administrator` user may grant the `Administrator` role.
- Roles of IAM-delegated accounts belong to the identity provider, which overwrites them at every login, so they are refused here.

## Users

- Users are addressed in the path by id only. Email and mobile lookups are query filters on the list endpoint. A path holding them would write personal data into every access log and would name different accounts over time as handles are reassigned. The query-string filters do reach gateway logs; that is accepted for this admin-only endpoint.
- There is no DELETE on a user. Disabling is `PATCH {"enabled": false}`. Hard deletion would orphan the records consuming apps linked to the user in `on_user_registered`.
- A user keeps at least one of email and phone number. Create requires one, and PATCH refuses to clear both, which would leave an account nobody can sign in to or recover.
- Creating a user issues a temporary password the user must replace at first sign-in. No tokens are issued.

## Role permissions

`/permissions` reads and edits `Custom DocPerm` rows, only for in-scope roles on in-scope doctypes.
