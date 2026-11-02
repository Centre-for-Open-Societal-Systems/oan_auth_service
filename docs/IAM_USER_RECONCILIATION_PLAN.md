# IAM user reconciliation: design and implementation plan

Status: proposed, not implemented.

How this app notices that a delegated user was removed or disabled in the
identity provider, disables the local `User`, and tells consumer apps so they
can deactivate their own records for that user.

Builds on `IAM_DELEGATED_LOGIN_PLAN.md` and `IAM_LOGIN_DISCOVERY_PLAN.md`.

## Problem

Delegated users are provisioned just in time: the first request with an IAM
token creates the local `User`, syncs its roles and runs the
`oan_auth_on_delegated_login` hooks. Consumers use that hook to create their own
records, for example `oan_grievance_service` creates officer desk rows from a
placement claim.

Nothing runs when a person is removed. A user deleted or disabled in Keycloak,
or stripped of every role for the row's `application`, never logs in again, so:

- the local `User` stays enabled until someone disables it by hand;
- consumer records stay active. In the grievance service, routing keeps
  assigning new cases to that officer's desk and nobody works them.

Role loss is only caught when the person makes another request
(`_provision_delegated_user` strips roles when the principal grants none). A
person who simply stops logging in is never caught.

## Facts this design depends on

- The local user name is `<sha256("{key}:{sub}")[:32]>@iam.internal`
  (`iam_users.user_name_for_sub`). It is one-way: neither `sub` nor the login
  option can be read back from a `User`. Given a `sub` and a row key, the user
  name can be computed.
- A disabled `User` is refused by the middleware on every request
  (`middleware.py`, `if not enabled`), even with an unexpired token. Disabling
  the `User` is the existing way to cut someone off before the token's `exp`.
- `OAN IAM Service` stores IAM's `base_url`, `provider_id`, `issuer`,
  `client_id` and `application`. It stores no identity-provider admin URL and no
  credentials. This app never talks to the identity provider directly.
- Login options differ in kind. A Keycloak staff realm has a user directory with
  roles and groups. eSignet (beneficiary login) has no roles, no groups and no
  API to list users; its users get `default_roles` only.

## Goals

- A scheduled job disables local delegated users who no longer hold access in
  the directory behind their login option.
- Consumers get a hook to deactivate their records for a removed user, and a
  hook when a removed user is restored.
- A failed, partial or suspicious directory read never disables anyone.
- Login options without a directory (eSignet) are left alone.

## Non-goals

- Syncing attribute or placement changes for active users. Those already apply
  through `oan_auth_on_delegated_login` on the user's next token.
- Real-time removal (SCIM push or Keycloak event listeners). The job can be
  complemented by them later; it stays as the safety net.
- Pre-provisioning users who have never logged in.

## Design

### Identity record

A new DocType `OAN IAM Identity`, one row per delegated user, written by
`resolve_user` on every successful provisioning:

| Field              | Type     | Notes                                                      |
| ------------------ | -------- | ---------------------------------------------------------- |
| `user`             | Link     | `User`, unique                                             |
| `login_option`     | Link     | `OAN IAM Service`                                          |
| `sub`              | Data     | The principal's `sub`                                      |
| `last_seen`        | Datetime | Updated at most once a day to avoid a write per request    |
| `missing_since`    | Datetime | Set by reconciliation on the first miss, cleared when seen |
| `disabled_by_sync` | Check    | Set when reconciliation disabled the `User`                |

This is the only place `sub` and the login option are stored; the user name
cannot be reversed. It is not a second source of truth for roles or access.

Users created before this table existed have no row. They get one on their next
request. Reconciliation ignores users without a row, so they are not covered
until then. This is stated in the README.

### Directory source per login option

New fields on `OAN IAM Service`, in a "Directory sync" section:

| Field                     | Notes                                                              |
| ------------------------- | ------------------------------------------------------------------ |
| `directory_sync`          | Select: empty (off), `IAM`, `Keycloak`. eSignet rows stay empty.   |
| `directory_admin_url`     | Keycloak only: e.g. `https://kc.example/admin/realms/<realm>`      |
| `directory_client_id`     | Keycloak only: service-account client                              |
| `directory_client_secret` | Keycloak only: `Password` field                                    |
| `max_removal_percent`     | Default 10. A run that would disable more stops and logs an error. |

- `IAM` (preferred): IAM exposes an endpoint listing the subs that hold roles for
  `application`. This keeps this app provider-neutral and reuses `base_url`. It
  does not exist yet; see Open questions.
- `Keycloak` (fallback): a client-credentials token for the service account,
  which needs only `view-users` and `query-users` in `realm-management`. The
  directory set is the union of
  `GET {admin_url}/clients/{client_uuid}/roles/{role}/users?first=&max=` over the
  client roles of `application`, keeping users with `enabled: true`. Roles that
  only come from `default_roles` are not counted: a row with `default_roles` and
  no `application` cannot be synced and is refused on save when sync is on.

The directory reader returns a set of subs or raises. It never returns a partial
set.

### Reconciliation job

`api/iam_reconcile.py::reconcile_all`, hourly from `scheduler_events`. For each
enabled row with `directory_sync` set:

1. Take a Redis lock per row (`oan_auth:iam_reconcile:{key}`). If held, skip.
2. Read the full directory set. On any error, timeout, non-2xx answer or
   malformed page, log once and stop this row. Nothing changes.
3. If the set is empty, stop and log. An empty directory is far more likely to
   be a wrong realm, client or role than a real state.
4. Load the `OAN IAM Identity` rows for this login option.
5. Present (`sub` in the set):
   - clear `missing_since`;
   - if `disabled_by_sync` is set: enable the `User`, clear the flag, run the
     restore hooks. Roles are resynced on the user's next request.
6. Missing (`sub` not in the set, `User` enabled):
   - first miss: set `missing_since`, do nothing else;
   - missing on the previous run too (two strikes): mark as a removal
     candidate.
7. If candidates exceed `max_removal_percent` of the row's identities, stop,
   log an error naming the row and the count, and disable nobody.
8. For each candidate, in its own transaction: run the removal hooks, set
   `User.enabled = 0`, set `disabled_by_sync`, commit. A hook that raises rolls
   back that user only, is logged, and is retried on the next run.
9. Log one summary per row: present, newly missing, disabled, restored, aborted
   and why.

Users an administrator disabled by hand have `disabled_by_sync = 0` and are never
re-enabled by the job.

### Consumer hooks

Two new hooks next to `oan_auth_on_delegated_login`, called in app install
order:

```python
# consumer hooks.py
oan_auth_on_delegated_user_removed = ["my_app.auth.on_delegated_user_removed"]
oan_auth_on_delegated_user_restored = ["my_app.auth.on_delegated_user_restored"]


def on_delegated_user_removed(user: str, login_option: str, reason: str) -> None:
    ...  # deactivate this app's records for `user`


def on_delegated_user_restored(user: str, login_option: str) -> None:
    ...  # usually nothing: the login hook rebuilds records on the next token
```

- `reason` is a short machine string: `missing_from_directory`,
  `disabled_in_directory`.
- Hooks run before the `User` is disabled, in the same transaction. Any
  exception rolls back that user's removal; it is retried next run. A removal
  must never leave the `User` disabled with consumer records still active.
- Hooks must be idempotent: a retried run calls them again.
- Hooks must not call the identity provider or IAM.

The middleware could also call the removal hooks when a request arrives whose
principal grants no roles (it already strips roles there). Left out of the first
version: on unsafe methods that path is rolled back, and the job catches the
user within two runs anyway.

### Re-enabling and cached login hooks

`oan_auth_on_delegated_login` runs once per token. A user restored while
holding an unexpired token for which the login hook already ran does not get
their consumer records back until their next token. The restore hook exists so a
consumer can rebuild immediately if that delay matters.

## Consumer: oan_grievance_service

Not part of this app; listed so the hook contract fits its first user.

- `on_delegated_login`: parse the placement claim, upsert officer desk rows,
  deactivate desk rows the claim no longer lists, refuse a staff role with no
  valid placement with `LoginDenied`. Never create desk rows for an eSignet
  login.
- `on_delegated_user_removed`: set `active = 0` on the user's `Grievance RBAC Assignment Officer` rows, then send the user's open cases back to their
  department's fallback desk so routing does not leave them with nobody.
- `on_delegated_user_restored`: nothing; desk rows return with the next token.
- The admin officer create and update API refuses IAM users, so desk rows have
  one writer.

## Security

- `directory_client_secret` is a `Password` field and is never returned by any
  API or written to logs.
- The service account is read-only on users. It cannot change Keycloak.
- The job only ever disables `@iam.internal` users that have an `OAN IAM Identity`
  row for the row being synced. Local password users are never touched.
- Fail closed for reading, fail safe for removal: an unreadable directory means
  no change, not "everyone removed".

## Implementation steps

1. `OAN IAM Identity` DocType; write it from `resolve_user`; `last_seen` throttled
   to once a day.
2. "Directory sync" fields on `OAN IAM Service`, with validation: Keycloak fields
   required when `directory_sync = Keycloak`; `application` required when sync is
   on.
3. Directory readers: `IAM` (once the endpoint exists) and `Keycloak`, each
   returning a full set of subs or raising.
4. `iam_reconcile.reconcile_all` with lock, empty-set guard, two strikes,
   removal threshold and per-user transactions.
5. `run_removed_hooks` and `run_restored_hooks` in `iam_users.py`, mirroring
   `run_login_hooks`.
6. `scheduler_events["hourly"]` entry.
7. README: the hooks, the coverage gap for users without an identity row, and
   the directory settings.

## Tests

- Directory read fails, times out or returns a malformed page: nobody disabled,
  `missing_since` untouched.
- Empty directory: nobody disabled.
- First miss sets `missing_since` only; second miss disables and runs the
  removal hook.
- A user who reappears after one miss: `missing_since` cleared, nothing else.
- Candidates above `max_removal_percent`: nobody disabled, error logged.
- Removal hook raises: that user stays enabled, others proceed.
- A user disabled by sync and back in the directory: enabled, restore hook run.
- A user disabled by an administrator and still in the directory: stays
  disabled.
- A row with `directory_sync` empty (eSignet): its users are never read or
  touched.
- A local password user is never touched.

## Open questions

- Can IAM expose a list endpoint (subs holding roles for an application)? If
  yes, the `Keycloak` source and its secret are not needed.
- Is "holds a client role of `application`" the right definition of access, or
  should membership of a Keycloak group decide it?
- Should the removal threshold be a percentage, an absolute count, or both? Small
  deployments with ten officers would trip 10% on one removal.
- Is hourly enough, or does any consumer need faster removal (then add a Keycloak
  event listener that calls the same removal path)?
