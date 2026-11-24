# Admin API rules

Business rules for `/api/v1/admin` (public `/v1/admin`). Code: `oan_auth_service/api/v1/admin.py`.

## Who can call it

Every endpoint checks that a role the caller holds grants the right on the doctype it changes, not a fixed role. Rules limited to the owner or to a permission level do not count, because Frappe lets every user read `User` under such a rule: `User` for the user and session routes, `Role` for the role routes, `Custom DocPerm` for the role-permission routes and the catalogue, and `User Permission` for the record restrictions (read, write, create or delete as the route does). System Manager and Administrator hold all of these, so they behave as before. A dedicated role, such as a central `OAN Administrator` created by an init script in each service, can be given exactly those permissions and nothing else. The service scope below, and the rules on Administrator accounts, apply to every caller.

The permission rules are written with Frappe's `add_permission`, `update_permission_property` and `reset_perms` rather than the desk's `permission_manager` endpoints, which insist on System Manager whatever the doctype permissions say. Frappe's own `/api/resource/User` is not a substitute: it does not accept this service's bearer tokens, and it knows nothing of the synthetic user id, the login email field, the linked Contact or the `on_user_registered` hook.

## Service scope

Only roles, doctypes and users of the calling service are visible.

- A role or doctype is in scope when its name is a configured prefix, or starts with the prefix and a space: prefix `A2C` matches `A2C Lead` and `A2C`, not `A2Cfoo`. The auth service adds the space, so a dependent app declares the bare prefix. This follows the `<Service> <Entity>` naming rule in `DEVELOPMENT_BEST_PRACTICES.md` §1.1. A user is in scope when they hold at least one such role.
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
- `DELETE /users/{id}` removes the account and its refresh tokens for good. It does not touch the records consuming apps linked to the user in `on_user_registered`, which may be left pointing at a deleted user, so prefer disabling with `PATCH {"enabled": false}`. It is refused for `Administrator`, the caller's own account, and accounts other records link to.
- A user keeps at least one of email and phone number. Create requires one, and PATCH refuses to clear both, which would leave an account nobody can sign in to or recover.
- Creating a user issues a temporary password the user must replace at first sign-in. No tokens are issued.

## Role permissions

`/permissions` reads and edits permission rules, only for in-scope roles on in-scope doctypes. How Frappe's standard and custom rules interact, and the freeze the first edit causes, is in `DEVELOPMENT_BEST_PRACTICES.md` §5.1.1.

- `POST /permissions/reset` deletes every custom rule of a doctype, for all roles, not only this service's. Admin changes on that doctype are lost.
- After every `bench migrate`, service doctypes whose custom rules differ from their DocType JSON are logged.
- Owner-only rules (`if_owner`) are listed but cannot be created or edited. A `PUT` on a role and doctype that already has an owner-only rule at the same level is refused, because Frappe would update whichever of the two rules it finds first.
- Audit: edits create a `Version` (this app enables `track_changes` on `Custom DocPerm`); deleted rules, including a reset, are kept in `Deleted Document`; each rule records who created it.

## Roles and record restrictions

- `POST /roles` creates a role whose name is in scope, with no desk access, and marks it `is_custom`. Desk access, home page and two-factor settings cannot be set here: desk access would let the role sign in to the Frappe desk.
- When a login option (`OAN IAM Service`, one per Keycloak realm) has an `application`, an `admin_client_id` and an `admin_client_secret`, `POST /roles` and `DELETE /roles/{role}` also create or remove the client role of the same name in that Keycloak client. The admin client is a service account of the option's own realm with rights to manage clients there; the secret is a Password field, encrypted at rest. Options without them are skipped. Keycloak is asked before the commit, so a refusal or an outage (502) leaves neither side changed, and the response lists the `realm/client` pairs touched under `keycloak`. `PATCH /roles/{role}` does not touch Keycloak.
- `DELETE /roles/{role}` works only on roles created through the API (`is_custom`), and only while no user holds them. Roles shipped by an app are refused.
- `PATCH /roles/{role}` sets `disabled`. Disabling a role removes it from every user who holds it, and enabling it again does not give it back. Tokens already issued keep the old role claim until they expire.
- Users holding a role are listed with `GET /users?role=`.
- `/users/{id}/user-permissions` manages Frappe User Permissions: restrict a user to one record of a service doctype. Both `allow` and `applicable_for` must be in-scope doctypes, and the record must exist. Restrictions on doctypes outside the service are not listed, and the caller's own account and `Administrator` cannot be changed.
- `GET /permissions/catalogue` returns the roles, doctypes and rights that `PUT /permissions` accepts. Standard rules are already part of `GET /permissions` (`source: standard`).
