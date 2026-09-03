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

# auth_hooks = ["oan_auth_service.api.middleware.validate_jwt_request"]


# Fixtures
# --------
# Roles owned by this app, exported to oan_auth_service/fixtures/ and committed.

# fixtures = []


# Scheduled Tasks
# ---------------
# Expired refresh tokens are deleted on a schedule; rows are only pruned here,
# never read back, so a daily sweep is enough.

# scheduler_events = {
# 	"daily": [
# 		"oan_auth_service.oan_auth.doctype.oan_user_refresh_token.oan_user_refresh_token.prune_expired",
# 	],
# }


# Testing
# -------

# before_tests = "oan_auth_service.setup.install.before_tests"
