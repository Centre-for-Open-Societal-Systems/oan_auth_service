"""Login, registration and token lifecycle endpoints.

These are whitelisted and must be listed as exempt paths by every consumer that
registers a namespace — they are how a caller obtains the token the middleware
demands, so requiring one here would deadlock.
"""


def login(usr: str, pwd: str, remember_me: bool = False):
	"""Authenticate and issue an access token plus a refresh token."""
	raise NotImplementedError


def register_user(**kwargs):
	"""Create a User and its role assignment, then issue a first token pair."""
	raise NotImplementedError


def refresh(refresh_token: str):
	"""Exchange a refresh token for a new pair, rotating the stored row.

	The presented token is single-use: the row backing it is deleted whether the
	exchange succeeds or fails, so a replayed token cannot mint a second pair.
	"""
	raise NotImplementedError


def logout(refresh_token: str):
	"""Revoke a refresh token. Access tokens expire on their own."""
	raise NotImplementedError


def forgot_password(usr: str):
	raise NotImplementedError


def reset_password(**kwargs):
	raise NotImplementedError
