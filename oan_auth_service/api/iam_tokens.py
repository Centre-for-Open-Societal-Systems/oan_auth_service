"""Client for the OpenG2P IAM services behind the login options.

Each enabled `OAN IAM Service` row (see config/settings.py) names one IAM API
(`base_url`), one of its identity providers (`provider_id`) and the exact
issuer of that provider's tokens. This module does every call this app makes
to IAM: validating a token, starting a login and logging out.

Validation. The frontend logs in against IAM, which proxies whichever identity
provider it is configured with (Keycloak, eSignet, ...). This app hands the
bearer token to the IAM of the row whose `issuer` equals the token's `iss`,
calls its `GET /auth/get_user_profile`, and gets back IAM's provider-neutral
principal,

    {"sub": ..., "name": ..., "client_roles": {"<application>": [roles]}}

IAM does the signature, issuer and expiry checks. It accepts any issuer in its
own `login_providers` table and skips `aud`, and the staff and agent IAMs
share that table, so the strict issuer match here is what separates one login
option's tokens from another's. A token whose issuer is on no enabled row
never reaches an IAM.

The principal is cached by row and token hash until the token's `exp`, so IAM
is asked once per token rather than once per request. IAM itself accepts a
token until `exp`, so the cache adds no revocation lag. The row lookup runs
before the cache, so disabling a row cuts off its tokens on the next request.
"""

import hashlib
import ipaddress
import time
from urllib.parse import urlparse

import frappe
import jwt
import requests

from oan_auth_service.api.tokens import TokenError
from oan_auth_service.config import settings

HTTP_TIMEOUT = 5
# One Error Log row per window during an IAM outage, not one per failing request.
OUTAGE_LOG_WINDOW_SEC = 60
_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class IAMUnavailableError(Exception):
	"""IAM could not be asked (unreachable, timed out or answered 5xx).

	Deliberately not a `TokenError`: the token was not judged, so the caller
	should get a 503, not a 401 that a frontend reads as an expired session.
	"""


class IAMBadResponseError(Exception):
	"""IAM answered a login or logout call with something this app cannot use.

	A 4xx or a malformed body means the row and the IAM disagree (wrong
	`base_url` or `provider_id`), not that IAM is down: a 502, not a 503.

	`upstream_status` and `upstream_body` hold IAM's answer.
	"""

	def __init__(self, detail: str = "", upstream_status: int | None = None, upstream_body=None):
		super().__init__(detail)
		self.upstream_status = upstream_status
		self.upstream_body = upstream_body


def _log_once(cache_key: str, window: int, title: str, message: str) -> None:
	"""Write one Error Log row per `window` seconds for `cache_key`, not one per request."""
	if frappe.cache.get_value(cache_key):
		return
	frappe.cache.set_value(cache_key, 1, expires_in_sec=window)
	frappe.log_error(title=title, message=message)


UPSTREAM_BODY_LIMIT = 2048


def _upstream(response) -> tuple[int | None, object]:
	"""IAM's status and body, as sent: parsed JSON when it parses, else its text cut to a safe length."""
	if response is None:
		return None, None
	try:
		return response.status_code, response.json()
	except ValueError:
		return response.status_code, (response.text or "")[:UPSTREAM_BODY_LIMIT]


def _iam_unavailable(detail: str) -> IAMUnavailableError:
	_log_once(
		"oan_auth:iam_outage_logged", OUTAGE_LOG_WINDOW_SEC, "oan_auth_service: IAM unavailable", detail
	)
	return IAMUnavailableError(detail)


def _iam_bad_response(service, detail: str, response=None) -> IAMBadResponseError:
	_log_once(
		f"oan_auth:iam_bad_response_logged:{service.key}",
		OUTAGE_LOG_WINDOW_SEC,
		"oan_auth_service: IAM bad response",
		f"Login option {service.key!r}: {detail}",
	)
	return IAMBadResponseError(detail, *_upstream(response))


def _is_loopback_host(host: str) -> bool:
	"""`localhost`, `*.localhost` (RFC 6761) or a loopback IP literal. No DNS.

	Same rule browsers use for "potentially trustworthy" origins (W3C Secure Contexts).
	"""
	if host == "localhost" or host.endswith(".localhost"):
		return True
	try:
		return ipaddress.ip_address(host).is_loopback
	except ValueError:
		return False


def is_secure_url(url: str) -> bool:
	"""Whether `url` is https, or http to a loopback host (see `_is_loopback_host`)."""
	try:
		parsed = urlparse(url)
	except ValueError:
		return False
	if parsed.scheme == "https":
		return True
	return parsed.scheme == "http" and _is_loopback_host(parsed.hostname or "")


def origin_of(url: str) -> str | None:
	"""`scheme://host[:port]` of an absolute http(s) URL, or None.

	The default port is dropped, so `https://a.org:443/x` and `https://a.org`
	have the same origin. URLs with credentials, whitespace, control
	characters or backslashes get None: browsers and urllib disagree on where
	such a URL's host ends, which is how open-redirect checks are bypassed.
	"""
	if not isinstance(url, str) or any(c.isspace() or c == "\\" or ord(c) < 32 for c in url):
		return None
	try:
		parsed = urlparse(url)
		port = parsed.port
	except ValueError:
		return None
	if (
		parsed.scheme not in _DEFAULT_PORTS
		or not parsed.hostname
		or parsed.username is not None
		or parsed.password is not None
	):
		return None
	host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
	origin = f"{parsed.scheme}://{host}"
	if port is not None and port != _DEFAULT_PORTS[parsed.scheme]:
		origin += f":{port}"
	return origin


def _require_https(base_url: str) -> None:
	"""Refuse to send bearer tokens or cookies to IAM over plain http.

	Rows are checked when saved; this repeats it at call time, so a row written
	around `validate()` still cannot leak a token. Loopback is exempt.
	"""
	if is_secure_url(base_url):
		return
	_log_once(
		"oan_auth:iam_insecure_url_logged",
		3600,
		"oan_auth_service: IAM base_url is not https",
		f"base_url={base_url!r} is plain http, so this login option is refused. Use an https URL.",
	)
	raise TokenError("IAM base_url must use https")


# Used when a token carries no readable `exp`: short enough that a revoked
# token does not linger, long enough to spare IAM a call per request.
FALLBACK_CACHE_TTL = 60


def peek_claims(token: str) -> dict:
	"""The token's payload without verifying anything, or `{}`.

	Only used to route the token. A forged claim gains nothing: IAM verifies the
	same token before anything is granted.
	"""
	try:
		claims = jwt.decode(token, options={"verify_signature": False})
	except jwt.PyJWTError:
		return {}
	return claims if isinstance(claims, dict) else {}


def peek_issuer(token: str) -> str | None:
	"""Return the token's `iss` without verifying anything, or None.

	Only used to route the token: our own issuer is verified in-process, any
	other goes to the IAM of the row with that issuer.
	"""
	iss = peek_claims(token).get("iss")
	return iss if isinstance(iss, str) else None


def service_for_token(token: str) -> frappe._dict:
	"""The enabled login option whose `issuer` is the token's `iss`, or raise TokenError.

	No IAM is called for a token this refuses. Reading `azp` unverified is safe:
	IAM verifies the same token next, and the request fails if it does not.
	"""
	claims = peek_claims(token)
	iss = claims.get("iss")
	azp = claims.get("azp")
	service = settings.iam_service_for_issuer(iss, azp=azp)
	if service is None:
		raise TokenError("Token issuer is not an enabled login option")
	if service.client_id and azp != service.client_id:
		raise TokenError(f"Token azp does not match the client_id of login option {service.key!r}")
	return service


def principal_cache_key(service, token: str) -> str:
	return f"oan_auth:iam_principal:{service.key}:{token_digest(token)}"


def token_digest(token: str) -> str:
	return hashlib.sha256(token.encode()).hexdigest()


# What is cached and exposed as `frappe.local.oan_auth_claims`: who the caller is and
# what IAM grants them. The person's details (phone, birthdate, national id, ...) are
# not kept: they reach `sync_profile` and the login hooks once per token, from
# `fetch_principal`, and the consuming app stores what it needs.
PRINCIPAL_CACHED_KEYS = ("sub", "name", "client_roles", "email")


def slim_principal(principal: dict) -> dict:
	return {k: principal[k] for k in PRINCIPAL_CACHED_KEYS if k in principal}


def get_principal(token: str, service) -> dict:
	"""The identity and roles `service`'s IAM gives for `token`, or raise TokenError if it rejects it.

	Cached until the token expires, without the person's details; see
	`fetch_principal` for those.
	"""
	key = principal_cache_key(service, token)
	principal = frappe.cache.get_value(key)
	if principal:
		return principal

	full = fetch_principal(token, service)
	try:
		if not hasattr(frappe.local, "_iam_full_principal"):
			frappe.local._iam_full_principal = {}
		frappe.local._iam_full_principal[token] = full
	except Exception:
		pass
	principal = slim_principal(full)
	frappe.cache.set_value(key, principal, expires_in_sec=seconds_until_expiry(token))
	return principal


def fetch_principal(token: str, service) -> dict:
	"""Ask IAM, and the provider's userinfo, for the full principal of `token`. Never cached."""
	# Refused locally, saving an IAM call per expired token: browsers keep
	# sending expired cookies. Unverified is enough to refuse; a forged future
	# `exp` gains nothing, IAM checks it next.
	exp = peek_claims(token).get("exp")
	if isinstance(exp, int | float) and exp <= time.time():
		raise TokenError("Token has expired")

	_require_https(service.base_url)

	try:
		response = requests.get(
			f"{service.base_url}/auth/get_user_profile",
			headers={"Authorization": f"Bearer {token}"},
			timeout=HTTP_TIMEOUT,
			allow_redirects=False,
		)
	except requests.RequestException as exc:
		raise _iam_unavailable(f"Could not reach IAM: {exc}")

	if response.status_code >= 500:
		raise _iam_unavailable(f"IAM answered {response.status_code}")
	if response.status_code != 200:
		raise TokenError(f"IAM rejected the token ({response.status_code})")

	try:
		principal = response.json()
	except ValueError:
		frappe.log_error(
			title="oan_auth_service: IAM bad response", message="IAM returned 200 with a non-JSON body"
		)
		raise TokenError("IAM returned a non-JSON response")
	if not isinstance(principal, dict):
		frappe.log_error(
			title="oan_auth_service: IAM bad response", message="IAM returned 200 with a non-object JSON body"
		)
		raise TokenError("IAM returned an unexpected response")
	if not principal.get("sub"):
		raise TokenError("IAM principal has no sub")

	_warn_if_no_application_roles(service, principal)
	return _with_userinfo(service, token, principal)


# What the identity provider's userinfo may add to the principal. It may never
# replace what the validated token and IAM said about who the caller is.
_USERINFO_RESERVED = frozenset(
	{"sub", "iss", "aud", "exp", "iat", "nbf", "client_roles", "scheme", "credentials"}
)
_USERINFO_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"]


def with_logged_in_user(service, token: str, principal: dict) -> dict:
	"""Add the claims of IAM's `/auth/get_logged_in_user` (email, given and family name) to `principal`.

	IAM's `/auth/get_user_profile` drops them, so without this the account never
	learns its login email. Asked only when the login hooks run (once per
	token), not by `fetch_principal`, which also serves every cache miss. Best effort: an IAM without the route, or any
	failure, leaves the principal as it was. The same rules as `_with_userinfo`
	apply: the subject must match and reserved claims are never replaced.
	"""
	try:
		response = requests.get(
			f"{service.base_url}/auth/get_logged_in_user",
			headers={"Authorization": f"Bearer {token}"},
			timeout=HTTP_TIMEOUT,
			allow_redirects=False,
		)
		claims = response.json() if response.status_code == 200 else None
	except (requests.RequestException, ValueError):
		return principal
	if not isinstance(claims, dict) or claims.get("sub") not in (None, principal.get("sub")):
		return principal
	given = {k: v for k, v in principal.items() if v not in (None, "")}
	extra = {k: v for k, v in claims.items() if k not in _USERINFO_RESERVED and v not in (None, "", {})}
	return {**extra, **given}


def _with_userinfo(service, token: str, principal: dict) -> dict:
	"""Add the identity provider's userinfo claims to `principal`, for a row with a `userinfo_url`.

	IAM's principal carries only the token's `sub`, `name` and roles. An eSignet
	login keeps the person's details (phone number, birthdate, national id, ...)
	at the provider's userinfo endpoint, which IAM does not ask. A Keycloak row
	has them in the token already and leaves `userinfo_url` empty.

	Best effort: any failure leaves the principal as IAM gave it, so a userinfo
	outage never blocks a sign-in. The caller caches the result per token.
	"""
	if not service.userinfo_url:
		return principal
	try:
		claims = _fetch_userinfo(service, token)
	except Exception as exc:
		_log_once(
			f"oan_auth:userinfo_failed_logged:{service.key}",
			OUTAGE_LOG_WINDOW_SEC,
			"oan_auth_service: userinfo unavailable",
			f"Login option {service.key!r}: {type(exc).__name__}: {exc}",
		)
		return principal
	if not claims:
		return principal
	if claims.get("sub") not in (None, principal.get("sub")):
		# Another person's data: never merged.
		frappe.log_error(
			title="oan_auth_service: userinfo sub mismatch",
			message=f"Login option {service.key!r}: userinfo is for another subject than the token.",
		)
		return principal
	# IAM's answer wins on a claim both gave, but an empty one (eSignet's token has no
	# `name`) does not hide the provider's.
	given = {k: v for k, v in principal.items() if v not in (None, "")}
	return {**{k: v for k, v in claims.items() if k not in _USERINFO_RESERVED}, **given}


def _fetch_userinfo(service, token: str) -> dict:
	"""Call the provider's userinfo endpoint with the access token and return its claims.

	A plain JSON answer is taken as it is. A signed (JWT) answer is checked
	against the row's `jwks_url` when it has one. Without it the signature is
	not checked: the answer came straight from the configured endpoint over
	https (or loopback) in reply to the caller's own token, and the subject is
	compared with the token's afterwards. That is for a provider that signs
	userinfo with a key it does not publish (this eSignet).
	"""
	url = service.userinfo_url
	if not is_secure_url(url):
		raise TokenError("userinfo URL must use https")

	response = requests.get(
		url, headers={"Authorization": f"Bearer {token}"}, timeout=HTTP_TIMEOUT, allow_redirects=False
	)
	if response.status_code != 200:
		raise TokenError(f"userinfo answered {response.status_code}")

	if "json" in response.headers.get("Content-Type", "") and not response.text.startswith("eyJ"):
		claims = response.json()
	elif service.jwks_url:
		if not is_secure_url(service.jwks_url):
			raise TokenError("keys URL must use https")
		signing_key = jwt.PyJWKClient(service.jwks_url, timeout=HTTP_TIMEOUT).get_signing_key_from_jwt(
			response.text
		)
		claims = jwt.decode(
			response.text,
			signing_key.key,
			algorithms=_USERINFO_ALGORITHMS,
			options={"verify_aud": False, "require": ["sub"]},
			issuer=service.issuer,
		)
	else:
		claims = jwt.decode(response.text, options={"verify_signature": False})
	if not isinstance(claims, dict):
		raise TokenError("userinfo is not an object")
	return claims


def _warn_if_no_application_roles(service, principal: dict) -> None:
	"""Log a row whose `application` matches nothing in the token.

	A wrong `application` is silent otherwise: the token validates and carries
	no roles. Rows that rely on `default_roles` alone (eSignet) have no
	`application` and never warn.
	"""
	if not service.application:
		return
	if (principal.get("client_roles") or {}).get(service.application):
		return
	_log_once(
		f"oan_auth:iam_no_application_roles_logged:{service.key}",
		3600,
		"oan_auth_service: IAM token has no roles for application",
		f"Login option {service.key!r}: a token of {principal.get('sub')!r} has no client_roles under "
		f"application {service.application!r}. Check that application is the Keycloak client id the "
		"roles are assigned under.",
	)


def start_login(service, return_url: str) -> str:
	"""Start `service`'s login at its IAM and return the identity provider URL to send the browser to.

	IAM does not check `return_url`; the gateway decides who may call this.
	"""
	try:
		_require_https(service.base_url)
	except TokenError as exc:
		raise _iam_unavailable(str(exc))

	try:
		response = requests.post(
			f"{service.base_url}/auth/start_authentication_transaction",
			params={"id": service.provider_id, "redirect_uri": return_url},
			timeout=HTTP_TIMEOUT,
			allow_redirects=False,
		)
	except requests.RequestException as exc:
		raise _iam_unavailable(f"Could not reach IAM: {exc}")

	if response.status_code >= 500:
		raise _iam_unavailable(f"IAM answered {response.status_code}")
	if response.status_code != 200:
		raise _iam_bad_response(
			service, f"start_authentication_transaction answered {response.status_code}", response
		)

	try:
		body = response.json()
	except ValueError:
		body = None
	redirect_url = body.get("redirectUrl") if isinstance(body, dict) else None
	if not isinstance(redirect_url, str) or urlparse(redirect_url).scheme not in ("http", "https"):
		raise _iam_bad_response(service, "start_authentication_transaction returned no http(s) redirectUrl")
	return redirect_url


def logout(service, cookies: dict[str, str]) -> tuple[list[str], str | None]:
	"""Log out of `service`'s IAM with the browser's IAM `cookies`.

	Returns IAM's `Set-Cookie` headers, which clear its cookies and must reach
	the browser, and the identity provider logout URL IAM redirected to, if any.
	IAM answering 401 (token expired, refresh failed) is not an error: there is
	no IAM session left to end.
	"""
	try:
		_require_https(service.base_url)
	except TokenError as exc:
		raise _iam_unavailable(str(exc))

	# The staff and agent IAM log out on GET (and redirect to the provider); the
	# beneficiary IAM only on POST (it clears its cookies and answers 200). A 405
	# to the GET means the other kind, so the same call is retried as POST.
	url = f"{service.base_url}/auth/logout"
	try:
		response = requests.get(url, cookies=cookies, timeout=HTTP_TIMEOUT, allow_redirects=False)
		if response.status_code == 405:
			response = requests.post(url, cookies=cookies, timeout=HTTP_TIMEOUT, allow_redirects=False)
	except requests.RequestException as exc:
		raise _iam_unavailable(f"Could not reach IAM: {exc}")

	if response.status_code >= 500:
		raise _iam_unavailable(f"IAM answered {response.status_code}")

	set_cookies = _set_cookie_headers(response)
	if response.status_code in _REDIRECT_STATUSES:
		location = response.headers.get("Location")
		if location and urlparse(location).scheme in ("http", "https"):
			return set_cookies, location
		return set_cookies, None
	if response.status_code == 401 or 200 <= response.status_code < 300:
		return set_cookies, None
	raise _iam_bad_response(service, f"logout answered {response.status_code}", response)


def refresh(service, cookies: dict[str, str]) -> tuple[bool, list[str]]:
	"""Refresh the browser's session at `service`'s IAM with its IAM `cookies`.

	IAM has no refresh endpoint: its auth middleware refreshes an expired access
	token on any authenticated route, from the session cookie, and answers with
	new cookies. `GET /auth/get_user_profile` is the cheapest such route.

	Returns whether IAM accepted the session, and its `Set-Cookie` headers,
	which carry the new tokens (none when the access token was still valid)
	and must reach the browser unchanged.
	"""
	try:
		_require_https(service.base_url)
	except TokenError as exc:
		raise _iam_unavailable(str(exc))

	try:
		response = requests.get(
			f"{service.base_url}/auth/get_user_profile",
			cookies=cookies,
			timeout=HTTP_TIMEOUT,
			allow_redirects=False,
		)
	except requests.RequestException as exc:
		raise _iam_unavailable(f"Could not reach IAM: {exc}")

	if response.status_code >= 500:
		raise _iam_unavailable(f"IAM answered {response.status_code}")
	set_cookies = _set_cookie_headers(response)
	if response.status_code == 200:
		return True, set_cookies
	if response.status_code in (401, 403):
		return False, set_cookies
	raise _iam_bad_response(
		service, f"get_user_profile answered {response.status_code} to a refresh", response
	)


def end_provider_session(logout_url: str) -> bool:
	"""Call the identity provider's logout URL server-to-server. Whether it answered without error.

	The URL is IAM's redirect to the provider's `end_session_endpoint` with
	`id_token_hint`. It is called only over https (or loopback), since the
	hint is the user's ID token.
	"""
	if not is_secure_url(logout_url):
		return False
	try:
		response = requests.get(logout_url, timeout=HTTP_TIMEOUT, allow_redirects=False)
	except requests.RequestException:
		return False
	return response.status_code < 400


def _set_cookie_headers(response) -> list[str]:
	"""Every `Set-Cookie` header of `response`, one string each.

	`response.headers` folds repeated headers into one comma-joined value, which
	cannot be split back safely (cookie `Expires` values contain commas).
	"""
	raw_headers = getattr(getattr(response, "raw", None), "headers", None)
	if raw_headers is not None and hasattr(raw_headers, "getlist"):
		return list(raw_headers.getlist("Set-Cookie"))
	value = response.headers.get("Set-Cookie")
	return [value] if value else []


# IAM's base cookie names (iam_core AuthCookieName). Read them through
# `cookie_name`, which applies a login option's prefix the way iam_core does.
ACCESS_COOKIE = "X-Access-Token"
ID_TOKEN_COOKIE = "X-ID-Token"
SESSION_COOKIE = "X-Session-Id"
CSRF_COOKIE = "X-CSRF-Token"
# iam_core never prefixes the CSRF header, only the cookie.
CSRF_HEADER = "X-CSRF-Token"
# The cookies IAM needs to log a session out (and, later, to refresh it).
SESSION_COOKIES = (ACCESS_COOKIE, ID_TOKEN_COOKIE, SESSION_COOKIE)


def cookie_name(base: str, prefix: str = "") -> str:
	"""`base` with an IAM cookie prefix applied (iam_core `cookie_name`)."""
	return f"{prefix or ''}{base}"


def seconds_until_expiry(token: str) -> int:
	# Read unverified: IAM has just verified this token, `exp` only sizes the cache.
	exp = peek_claims(token).get("exp")
	if not isinstance(exp, int | float) or not exp:
		return FALLBACK_CACHE_TTL
	return max(1, int(exp - time.time()))
