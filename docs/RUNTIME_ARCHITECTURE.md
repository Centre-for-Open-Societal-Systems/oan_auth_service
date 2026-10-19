# Runtime Architecture

How an OAN Frappe app runs in production. The processes are independent and coordinate
through Redis and MariaDB.

## Rules

- **Web workers are stateless.** Auth is a JWT, counters and rate limits are in Redis,
  data is in MariaDB. Never keep per-user state in process memory, so any number of
  workers can serve any request.
- **Exactly one scheduler.** Two schedulers run every timed job twice.
- **Queue Redis and cache Redis are separate.** The queue Redis must not evict keys; the
  cache Redis may.
- **Split workers by queue** so one slow external service cannot block the others.
- **Uploaded files go on shared storage** (object storage or a shared volume) before the
  app runs on more than one pod. Local disk works for one pod only.
- **Counters for hot dashboards** may live in Redis and change as records change. Counting
  on write drifts (a failed hook, a direct DB change), so pair it with a scheduled job
  that recounts from the database and corrects the value.
