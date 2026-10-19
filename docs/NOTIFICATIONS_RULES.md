# Notifications rules

Business rules for `/api/v1/notifications`. Code: `oan_auth_service/api/v1/notifications.py`.

- Notifications are Frappe `Notification Log` records, so the desk bell and realtime push keep working.
- Every endpoint needs a valid token and only touches records where `for_user` is the caller. Another user's record answers 404, the same as a missing one, so ids cannot be probed.
- There is no create endpoint. Apps write notifications in process through `notify_users`, which never raises, so a business write is not failed by a notification. A failure is logged with its traceback in the Error Log.
- `notify_users` skips the acting user.
- Bulk read, unread and delete take either `ids` or `all=true`. Sending neither, or both, is an error, so a client bug cannot clear every record with an empty body. `ids` holds at most 500 entries.
- `message` carries `email_content` unchanged and can contain HTML. Clients must sanitize it before rendering.
