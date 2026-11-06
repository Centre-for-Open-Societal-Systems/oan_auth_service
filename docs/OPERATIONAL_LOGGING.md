# Operational Logging

Structured logs for every OAN app on a site: one JSON object per line, a correlation id on everything
written during a request or a job, and no credentials or personal data. The code is in
[`api/operational_log.py`](../oan_auth_service/api/operational_log.py) (the logger, masking and scrubbing,
`emit`, `log_error`) and [`api/request_log.py`](../oan_auth_service/api/request_log.py) (the request hooks).
An app adds its own events by calling `emit`; see [Adding a log line](#adding-a-log-line).

It is built on Frappe's own logger. In a container set `FRAPPE_STREAM_LOGGING=1` and the lines go to
stderr; otherwise they go to `logs/oan.log` in the bench. It sits beside the **Error Log** doctype, which
stays the place an administrator reads a traceback in the desk; `log_error` writes both.

## Reading a line

```json
{
  "ts": "2026-11-06T06:10:12.106+00:00",
  "level": "WARNING",
  "logger": "oan",
  "event": "security.auth_failure",
  "correlation_id": "cb272429-f81a-4a6f-9d93-09b7781445de",
  "site": "erpnext16.local",
  "method": "POST",
  "path": "/api/v1/auth/login",
  "status": 401,
  "error_code": "AUTHENTICATION_ERROR",
  "auth_scheme": "none",
  "client_ip": "127.0.0.0",
  "attempted_user": "j***@example.com"
}
```

`ts` is UTC. `event` is `<area>.<what>`. Every line written during a request or a job carries
`correlation_id`. Fields that are empty are left out.

```bash
# Everything one request did, from the id in its response or in a support ticket
jq -c 'select(.correlation_id == "cb272429-f81a-4a6f-9d93-09b7781445de")' logs/oan.log
# Slow or failing requests
jq -c 'select(.event == "http.request" and (.slow or .status >= 500))' logs/oan.log
# Failed sign-ins, by masked account
jq -r 'select(.event == "security.auth_failure") | .attempted_user // empty' logs/oan.log | sort | uniq -c | sort -rn
```

## Correlation id

`request_log.begin` is a `before_request` hook. Frappe runs those before the auth hooks, so a request the
auth layer refuses has an id.

- A caller's `X-Request-Id` is adopted when it is 8 to 64 characters of letters, digits and `. _ : -`.
  Anything else (a space, a quote, a line break, too long) is replaced, because an id is written into every
  log line and a free-form one would let a caller forge lines.
- Otherwise a UUID4 is generated.
- It is stored in `frappe.local.request_id`. So it is the `request_id` in every JSON envelope and the
  `X-Request-Id` response header, including on 401, 404 and framework error pages.
  `handle_api_errors` takes the id through the same `ensure_correlation_id`, so there is one mechanism.
- Frappe starts the session before it runs `before_request` hooks, and maintenance mode stops a request
  before them too. A CSRF or session failure, or a site in maintenance, never reaches `begin`. The
  `after_request` hook (`end`) still runs for it: it adopts or mints the id there, returns it in the header,
  and logs the request **without `duration_ms`** (nothing started the clock).
- An app that runs scheduled work sets its own id for the run (the grievance service uses
  `job-<name>-<12 hex>`), so every line the run writes can be pulled with one filter.

The APISIX gateway does not generate an id today. Turning on its `request-id` plugin would make the
gateway's own log and this one share ids end to end.

## Events

| Event                                                  | Level   | When                                                                          |
| ------------------------------------------------------ | ------- | ----------------------------------------------------------------------------- |
| `http.request`                                         | by code | Every request under `/api/v1/` or a namespace an app registered.              |
| `security.auth_failure`                                | WARNING | Response 401, with the auth scheme tried and, for a sign-in, the masked user. |
| `security.permission_denied` / `security.rate_limited` | WARNING | Response 403 / 429.                                                           |
| `error`                                                | ERROR   | Every `log_error`: `title`, `exception`, `summary` (last line), `detail`.     |

`http.request` is INFO for 2xx and 3xx, WARNING for 4xx and for any request slower than
`oan_slow_request_ms`, ERROR for 5xx. A path ending in `/health` or `/ping` is DEBUG when it succeeds, so a
monitor polling every few seconds does not fill the log. Desk pages, assets and Frappe's own methods are
not logged. Apps add their own events (the grievance service logs `sla.*`, `escalation.*` and `job.*`).

**Error rows and lines.** `log_error` is called from `except` blocks, so it never raises: if the Error Log
insert fails, the line says `error_log_failed` instead. The title is cut to the 140 characters the column
holds, marker included. With no message the row holds what `frappe.log_error` would have stored, scrubbed,
with the correlation id on its first line. When text is too long the **end** is kept (the exception message
is a traceback's last line): up to 30,000 characters in the row, and in the line the last line as `summary`
plus up to 4,000 characters of the traceback as `detail`.

Whether a traceback lists each frame's local variables is Frappe's decision. From Frappe 16.55,
`get_traceback(with_context=True)` leaves them out unless the site is in `developer_mode`; older versions
always include them. Either way what Frappe returns is scrubbed before it is stored: variables named for a
credential or a personal field (`submitter_name`, `contact_email`, `description`, `password`...) are
blanked, as are personal keys inside a dict dump.

## What is never logged

- Request or response **bodies**. Only the _names_ of the fields sent (`param_names`) and the byte sizes.
- **Header values**, except `User-Agent` (trimmed to 120 characters and scrubbed). The `Authorization` and
  `Cookie` headers are never read beyond the scheme word (`bearer`, `token`, `basic`, `cookie`).
- **Query and form values**, and the response `message` (an error message can echo what the caller sent). An
  error response contributes only its `code`.
- Passwords, tokens (access, refresh, API key and secret, CSRF), OTPs, session ids, `Authorization` and
  `Cookie` values, in any field. This holds even if a caller passes one by mistake.

What is logged is masked:

| Data                               | Logged as                                                                           |
| ---------------------------------- | ----------------------------------------------------------------------------------- |
| User id                            | `j***@example.com`, `***67` for a phone-derived id                                  |
| Email, mobile number               | `j***@example.com`, `***44` (last two digits)                                       |
| Names                              | `A*** K***`                                                                         |
| National ID, registration, account | `***56` (last two characters)                                                       |
| Description, address, message ...  | `[MASKED]`                                                                          |
| Client address                     | IPv4 to its /24 (`196.188.12.0`), IPv6 to its /48                                   |
| Path                               | emails and runs of 10 or more digits are masked (an officer is `/officers/<email>`) |

Free text (exception messages, tracebacks, paths) goes through `scrub_text`, which finds things by their
shape:

- **Credentials:** a JWT; an `Authorization` header or dict key with its value (`Bearer`, `Basic` or `token`
  scheme); a long opaque `Bearer <token>`; and `password=...`-style pairs for password, secret, token, api
  key, OTP and similar names. The plain words _token_, _basic_ and _bearer_ in a sentence
  ("Invalid token provided") are left alone.
- **Emails.**
- **Phone numbers:** Ethiopian mobiles (`0911223344`, `+251911223344`), an international number with a `+`
  (spaced, dashed or run together), a national number written in groups (`0911 223 344`), and a 16-digit
  Fayda id. Epoch times, other long ids, dates and a nine-character ticket number are left alone.

Scrubbing runs in time linear in the text. At most four times the limit is scanned (a traceback with a large
local variable can be megabytes), every pattern starts only at the beginning of a name or a run of address
characters, and its prefixes and suffixes are bounded.

## Adding a log line

```python
import logging

from oan_auth_service.api import operational_log as oplog

oplog.emit("notification.dispatched", record=doc.name, channel="SMS")        # INFO
oplog.emit("security.something_odd", logging.WARNING, user=frappe.session.user)

try:
    ...
except Exception:
    oplog.log_error(title="What failed")                                      # not frappe.log_error
```

Use `oplog.log_error` instead of `frappe.log_error`: it stores the same Error Log row, but scrubbed and with the
correlation id on its first line, and writes the structured line. Pick the identifying fields; do not log a
body, a header, a whole document or `frappe.form_dict`. Values you do pass are redacted by key name and
pattern, which is a safety net, not a licence. `emit` never raises, but building its arguments is the caller's
work: do not put anything in a field that can fail.

## Configuration

- **Level.** Frappe sets a logger's level from `frappe.log_level` and, with it unset, leaves a production
  bench at ERROR. `get_logger()` sets `frappe.log_level` to INFO once if nothing else has; a level an
  operator set through `frappe.utils.logger.set_log_level` is kept. This is the same variable
  `set_log_level` sets, assigned directly: `set_log_level` also empties Frappe's logger cache, which would
  let a logger that already exists gain a second set of handlers. Every Frappe logger created afterwards
  takes the same level.
- **Rotation and retention.** Frappe's: with `FRAPPE_STREAM_LOGGING=1` a plain stream handler (no rotation;
  the container runtime and log collector own it), otherwise a rotating file of 100 KB, 20 files. There is no
  setting of ours.
- **`oan_slow_request_ms`** in site config, default 2000: a request at least this slow is logged as slow, at
  WARNING. A missing, non-numeric, zero or negative value means the default.

## Cost

Per request, over the cost of building the request: about 0.05 ms when the level means nothing is written (an
id, a clock, and a level check), and about 0.55 ms at INFO with a synchronous file write. A response body is
read only for a 4xx or 5xx, and only when it is a small JSON document.

## Known gaps

- The reason the auth layer refuses a token (expired, forged, revoked) stays in its Error Log; the response
  and the log say only `401`. Having `_reject` store a reason code on `frappe.local` would let
  `security.auth_failure` carry it.
- Every refusal still writes an Error Log row (a database write an unauthenticated caller can trigger at
  will).
- A 500 raised outside `handle_api_errors` is logged by Frappe in the Error Log without the correlation id;
  the matching `http.request` line (status 500) carries it, and the two can be paired by time and path.
- Masked users are not unique: two officers with the same initial and domain look alike. A stable keyed
  handle (an HMAC of the user id) would tell them apart; it is left for a follow-up.
