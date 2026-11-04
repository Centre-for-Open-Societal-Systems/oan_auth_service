# Idempotency keys

`@idempotent` (`oan_auth_service/api/idempotency.py`) makes a retried write run once. Usage is in
the README. This note records how it works and what it does not cover.

## Why the database and not Redis

The key and the endpoint's writes commit or roll back together. A key in Redis cannot: written
before the commit, it can report "done" for a record that was rolled back; written after, it is
lost if the worker dies in between and the retry duplicates.

## Behaviour

| Situation                                    | Result                                                        |
| -------------------------------------------- | ------------------------------------------------------------- |
| No header                                    | Endpoint runs as before (400 with `required=True`)            |
| Malformed key (not 8-128 of `A-Za-z0-9._:-`) | 400                                                           |
| First request                                | Row inserted, endpoint runs, response stored                  |
| Endpoint raises                              | `handle_api_errors` rolls back; row gone; retry runs as first |
| Endpoint returns status >= 400               | Row deleted; retry runs as first                              |
| Retry, first already committed               | Stored response, `Idempotency-Replayed: true`                 |
| Retry, first still running                   | Waits `IN_FLIGHT_WAIT` (1s) for it, then 409                  |
| Same key, different body                     | 422                                                           |

The row is named by `sha256(caller | method | path | key)`, so another user, method or route with the
same key is a separate request. A guest is scoped by IP address.

## Data kept

Only the hash, method, path, a hash of the body, the status and the response. The response is
**encrypted** with the site's encryption key, since it can hold names, phone numbers and IDs, and
the row carries no user name. Rows are deleted by an hourly job (`purge_expired`) once older than
`oan_idempotency_retention_hours` in site_config.json (default 24), which is also how long a retry is
recognised. Set it to the longest a mobile client may queue a retry offline, and no longer. Changing the site's `encryption_key` makes the stored
responses unreadable, so replays of keys younger than a day fail.

## Observability

Each decision is one dict in `logs/oan_idempotency.log`:
`{outcome, route, method, key, status, duration_ms}`. `route` is the URL template and `key` the first
8 characters of the row hash; the client's key and the path are never logged. When the site has
`monitor` on, `idempotency=<outcome>` is also added to Frappe's per-request record, which carries
the request duration, so replay rate and latency can be read from `logs/monitor.json.log`.

Outcomes: `first`, `replay`, `in_progress`, `mismatch`, `released`, `invalid_key`, `key_required`.

## Not covered

- **External side effects.** An SMS or a call to another service made before a rollback happens
  again on the retry. Endpoints that send them need their own guard.
- **An explicit `frappe.db.commit()` inside the endpoint** commits the reservation before the
  response is stored. A retry then gets 409 until the day is up.
- **MariaDB only** for the short in-flight wait. On other databases a retry waits for the full lock
  timeout.
- **Rows are written on every keyed request.** Expect about 2-4 KB each (an estimate, not measured),
  so a day of 1M keyed requests is about 3 GB. The purge is batched (2000 rows per commit) and hourly,
  and the table stays bounded because the retention is short. If it is still too large, shorten the
  retention first, then store a record reference instead of the response.
