app_name = "oan_auth_service"
app_title = "OAN Auth Service"
app_publisher = "OpenAgriNet"
app_description = "JWT authentication service for OAN services"
app_email = "admin@openagrinet.org"
app_license = "mit"


# Apps
# ------------------
# Consuming apps declare `required_apps = ["oan_auth_service"]` so bench installs
# this one first and the refresh-token doctype exists before they migrate.

# required_apps = []


# Authentication
# --------------
# Registered once here rather than in each consuming app: the hook fires for
# every request, and the middleware decides whether the path belongs to a
# registered namespace. Consuming apps register their namespace and exempt paths
# via api.middleware.register_namespace() — see that module.

auth_hooks = ["oan_auth_service.api.middleware.validate_jwt_request"]

# Revokes refresh tokens when a session ends through Frappe's own logout. Without
# it a desk logout drops the session cookie but leaves every refresh token live
# for its full lifetime, so a user who believes they logged out has not.
on_logout = "oan_auth_service.api.v1.auth.on_logout"


# Installation
# ------------
# Adds User.oan_login_email on fresh sites. `bench install-app` marks patches as
# applied without running them (frappe/installer.py:357), so the patch that adds
# this field covers upgrades only — new sites, and the site CI builds each run,
# depend on this hook. Both call the same idempotent function.

after_install = "oan_auth_service.setup.install.after_install"


# Fixtures
# --------
# Roles owned by this app, exported to oan_auth_service/fixtures/ and committed.

# fixtures = []


# Scheduled Tasks
# ---------------
# Expired refresh tokens are deleted on a schedule; rows are only pruned here,
# never read back, so a daily sweep is enough.

scheduler_events = {
	"daily": [
		"oan_auth_service.oan_auth.doctype.oan_user_refresh_token.oan_user_refresh_token.prune_expired",
	],
}


# Testing
# -------

# before_tests = "oan_auth_service.setup.install.before_tests"
