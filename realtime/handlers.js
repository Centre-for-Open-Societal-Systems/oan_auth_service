// Socket.io handlers loaded by Frappe's realtime server (frappe/realtime/index.js loads
// `<app>/realtime/handlers.js` for every app installed on the site). They run once per
// socket, after Frappe has authenticated it.
//
// Frappe checks a socket's token once, at the handshake, and then keeps the socket open
// for as long as the client stays connected. This closes a socket authenticated with a
// bearer token (an oan_auth_service token or an OpenG2P IAM token) when that token
// expires. The client then reconnects with a fresh token, which is checked again.

// setTimeout fires at once for a delay above 2^31 - 1 ms (about 24.8 days).
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

// `exp` (seconds) of a JWT, or null. Not verified: Frappe verified this token through
// get_user_info just before this runs, and `exp` only sets when the socket is closed.
function token_expiry(authorization_header) {
  const match = /^Bearer\s+(\S+)$/i.exec(authorization_header || "");
  if (!match) return null;
  const payload = match[1].split(".")[1];
  if (!payload) return null;
  try {
    const exp = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    ).exp;
    return typeof exp === "number" ? exp : null;
  } catch {
    return null;
  }
}

function close_at_token_expiry(socket) {
  if (socket.user === "Guest") return;
  const exp = token_expiry(socket.authorization_header);
  // A desk `sid` session, or a token without `exp`: Frappe's own session rules apply.
  if (exp === null) return;

  const ms = exp * 1000 - Date.now();
  if (ms <= 0) {
    socket.disconnect(true);
    return;
  }
  const timer = setTimeout(
    () => socket.disconnect(true),
    Math.min(ms, MAX_TIMEOUT_MS)
  );
  socket.on("disconnect", () => clearTimeout(timer));
}

module.exports = function (socket) {
  close_at_token_expiry(socket);
};

module.exports.token_expiry = token_expiry;
