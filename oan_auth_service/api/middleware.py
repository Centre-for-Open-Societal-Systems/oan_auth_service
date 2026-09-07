"""JWT validation bound to Frappe's auth_hooks.

One hook serves every consuming app. Each app registers the API namespace it
owns plus the paths within it that are reachable without a bearer token; the
middleware matches the incoming path against that registry and leaves anything
unregistered — desk, standard Frappe APIs — to Frappe's own auth.

Registration keeps this app free of any knowledge of its consumers, which is
what lets it be shared without becoming a dependency in both directions.
"""

# namespace prefix -> config for that consumer.
_NAMESPACES: dict[str, dict] = {}


def register_namespace(prefix: str, exempt_paths: list[str] | None = None, revocation_check=None):
	"""Declare an API namespace as JWT-protected.

	prefix           e.g. "/api/method/grievance_backend."
	exempt_paths     full paths reachable without a token (login, refresh, webhooks)
	revocation_check optional callable(user) -> str | None; a returned string is
	                 the rejection reason. Lets a consumer invalidate live tokens
	                 on its own conditions without this app knowing the rule.
	"""
	raise NotImplementedError


def validate_jwt_request(request=None):
	"""Entry point registered as `auth_hooks` in hooks.py."""
	raise NotImplementedError
