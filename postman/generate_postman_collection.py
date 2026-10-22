#!/usr/bin/env python3
"""generate_postman_collection.py.

Builds the Postman collection (oan_auth_collection.json) from
openapi_v1.yaml (the internal spec, whose paths a bench site serves), so the collection cannot drift from the routes the way
the hand-maintained one did.

The spec supplies every request: method, path, auth, folder and description.
This script adds only what a spec cannot say: example bodies wired to
environment variables, and the post-response scripts that carry tokens and ids
from one request to the next (login -> access_token, create user ->
target_user_id, ...).

Usage (from the bench root, after regenerating the spec):
    env/bin/python apps/oan_auth_service/postman/generate_postman_collection.py
"""

import json
import re
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
# The internal spec: its paths are Frappe's (`/api/v1/...`), which `base_url` (a bench
# site) serves. The public spec's `/v1/...` paths exist only behind the gateway.
SPEC_PATH = REPO_ROOT / "openapi" / "openapi_v1.yaml"
COLLECTION_PATH = SCRIPT_DIR / "oan_auth_collection.json"
ENVIRONMENT_PATH = SCRIPT_DIR / "oan_auth_environment.json"

# Fixed so regenerating produces a diff only when the content changes, and a
# re-import replaces the collection in Postman instead of adding a second one.
COLLECTION_ID = "9b3c4f9a-6562-42ea-a45a-c6e3952f41b2"

# Old paths kept serving for existing clients; documenting them twice would only
# invite new callers onto them.
LEGACY_PATHS = {"/api/v1/auth/forgot-password", "/api/v1/auth/reset-password"}

# Folder order, and request order inside each folder, follow a usable flow
# rather than spec order: register before login, create user before editing it.
# Password Recovery runs last: "Replace a temporary password" needs the temporary
# password the Admin folder issues.
FOLDER_ORDER = [
	"System & Keys",
	"Authentication & Session",
	"Identity & Profile",
	"Notifications",
	"Admin",
	"Password Recovery",
]
REQUEST_ORDER = [
	("GET", "/api/v1/auth/health"),
	("GET", "/api/v1/auth/keys"),
	("GET", "/api/v1/auth/metadata"),
	("POST", "/api/v1/auth/register"),
	("POST", "/api/v1/auth/login"),
	("POST", "/api/v1/auth/refresh"),
	("POST", "/api/v1/auth/logout"),
	("GET", "/api/v1/auth/iam/providers"),
	("POST", "/api/v1/auth/iam/login"),
	("POST", "/api/v1/auth/password/forgot"),
	("POST", "/api/v1/auth/password/reset"),
	("POST", "/api/v1/auth/password/initial"),
	("GET", "/api/v1/auth/me"),
	("GET", "/api/v1/notifications"),
	("PATCH", "/api/v1/notifications"),
	("DELETE", "/api/v1/notifications"),
	("GET", "/api/v1/notifications/{notification_id}"),
	("PATCH", "/api/v1/notifications/{notification_id}"),
	("DELETE", "/api/v1/notifications/{notification_id}"),
	("GET", "/api/v1/admin/roles"),
	("POST", "/api/v1/admin/users"),
	("GET", "/api/v1/admin/users"),
	("GET", "/api/v1/admin/users/{user_id}"),
	("PATCH", "/api/v1/admin/users/{user_id}"),
	("GET", "/api/v1/admin/users/{user_id}/roles"),
	("POST", "/api/v1/admin/users/{user_id}/roles"),
	("DELETE", "/api/v1/admin/users/{user_id}/roles/{role}"),
	("POST", "/api/v1/admin/users/{user_id}/temporary-password"),
	("DELETE", "/api/v1/admin/users/{user_id}/sessions"),
	("GET", "/api/v1/admin/permissions"),
	("PUT", "/api/v1/admin/permissions"),
	("DELETE", "/api/v1/admin/permissions"),
	("POST", "/api/v1/admin/permissions/reset"),
]

# Path parameter -> environment variable.
PATH_VARIABLES = {"user_id": "target_user_id", "role": "target_role", "notification_id": "notification_id"}

# Example bodies. Values are Postman variables wherever a later request depends
# on them, so a run through the folder works without editing anything.
BODIES = {
	("POST", "/api/v1/auth/register"): {
		"full_name": "{{user_full_name}}",
		"email": "{{user_email}}",
		"phone_number": "{{user_phone_number}}",
		"password": "{{user_password}}",
		# Not part of the auth service: extra fields reach every on_user_registered hook,
		# and the grievance app's refuses a farmer account without a 16-digit Fayda ID.
		"fayda_id": "{{user_fayda_id}}",
	},
	("POST", "/api/v1/auth/login"): {
		"usr": "{{user_email}}",
		"pwd": "{{user_password}}",
		"remember_me": False,
	},
	("POST", "/api/v1/auth/refresh"): {"refresh_token": "{{refresh_token}}"},
	("POST", "/api/v1/auth/logout"): {"refresh_token": "{{refresh_token}}"},
	("POST", "/api/v1/auth/iam/login"): {"key": "{{iam_login_key}}", "return_url": "{{iam_return_url}}"},
	("POST", "/api/v1/auth/password/forgot"): {"usr": "{{user_email}}"},
	("POST", "/api/v1/auth/password/reset"): {
		"key": "{{reset_key}}",
		"new_password": "{{user_new_password}}",
	},
	("POST", "/api/v1/auth/password/initial"): {
		"usr": "{{target_email}}",
		"current_password": "{{temporary_password}}",
		"new_password": "{{user_new_password}}",
	},
	("POST", "/api/v1/admin/users"): {
		"full_name": "Onboarded User",
		"email": "{{target_email}}",
		# Also read by the grievance app's registration hook, which wants a mobile number.
		"phone_number": "{{target_phone_number}}",
		"roles": ["{{target_role}}"],
		"fayda_id": "{{target_fayda_id}}",
	},
	("PATCH", "/api/v1/admin/users/{user_id}"): {"first_name": "Renamed", "enabled": True},
	("POST", "/api/v1/admin/users/{user_id}/roles"): {"roles": ["{{target_role}}"]},
	("POST", "/api/v1/admin/users/{user_id}/temporary-password"): {},
	("PATCH", "/api/v1/notifications"): {"all": True, "read": True},
	("DELETE", "/api/v1/notifications"): {"all": True},
	("PATCH", "/api/v1/notifications/{notification_id}"): {"read": True},
}

# Query parameters shown, disabled, so the request runs as-is and each filter
# is one click away.
QUERY_EXAMPLES = {
	"page": "1",
	"page_size": "20",
	"search": "",
	"email": "{{target_email}}",
	"phone_number": "",
	"role": "{{target_role}}",
	"enabled": "true",
	"status": "unread",
}

SAVE_TOKENS = [
	"var data = {}; try { data = pm.response.json().data || {}; } catch (e) {}",
	"if (data.access_token) { pm.environment.set('access_token', data.access_token); }",
	"if (data.refresh_token) { pm.environment.set('refresh_token', data.refresh_token); }",
]

# The access token stays: it is stateless and lives until it expires, and Identity
# & Profile runs next. Only the refresh token, now revoked, is dropped.
CLEAR_TOKENS = [
	"pm.environment.unset('refresh_token');",
]

SAVE_TARGET = [
	"var data = {}; try { data = pm.response.json().data || {}; } catch (e) {}",
	"if (data.user) { pm.environment.set('target_user_id', data.user); }",
	"if (data.temporary_password) { pm.environment.set('temporary_password', data.temporary_password); }",
]

SAVE_TEMPORARY_PASSWORD = [
	"var data = {}; try { data = pm.response.json().data || {}; } catch (e) {}",
	"if (data.temporary_password) { pm.environment.set('temporary_password', data.temporary_password); }",
]

SAVE_NOTIFICATION = [
	"var data = {}; try { data = pm.response.json().data || {}; } catch (e) {}",
	"if (data.items && data.items.length > 0) { pm.environment.set('notification_id', data.items[0].id); }",
]

AFTER_RESPONSE = {
	("POST", "/api/v1/auth/register"): SAVE_TOKENS,
	("POST", "/api/v1/auth/login"): SAVE_TOKENS,
	("POST", "/api/v1/auth/refresh"): SAVE_TOKENS,
	("POST", "/api/v1/auth/logout"): CLEAR_TOKENS,
	("GET", "/api/v1/notifications"): SAVE_NOTIFICATION,
	("POST", "/api/v1/admin/users"): SAVE_TARGET,
	("POST", "/api/v1/admin/users/{user_id}/temporary-password"): SAVE_TEMPORARY_PASSWORD,
}

# Variables the collection reads, with a note on where each comes from. Merged
# into the environment file so it always lists every one.
VARIABLES = {
	"base_url": ("default", "Site URL, e.g. http://testsite.localhost:8000"),
	"user_email": ("default", "Generated when blank. Register creates this account; Login uses it"),
	"user_password": ("secret", "Generated when blank"),
	"user_full_name": ("default", "Generated when blank"),
	"user_phone_number": ("default", "E.164. Generated when blank"),
	"user_new_password": ("secret", "Generated when blank. Used by Reset Password and Set Initial Password"),
	"reset_key": ("secret", "From the password reset email link"),
	"iam_login_key": ("default", "Key of an enabled OAN IAM Service row, e.g. staff"),
	"iam_return_url": ("default", "Absolute URL on one of that row's return origins"),
	"admin_username": ("default", "A System Manager, used by Admin > Sign in as admin"),
	"admin_password": ("secret", "Password of admin_username"),
	"admin_access_token": ("secret", "Set by Admin > Sign in as admin"),
	"access_token": ("secret", "Set by Register, Login and Refresh"),
	"refresh_token": ("secret", "Set by Register, Login and Refresh"),
	"target_email": ("default", "Generated when blank. Login email of the user the admin onboards"),
	"user_fayda_id": ("default", "16 digits, new each run. Needed by the grievance app's registration hook"),
	"target_fayda_id": (
		"default",
		"16 digits, new each run. Needed by the grievance app's registration hook",
	),
	"target_phone_number": ("default", "E.164, new each run. Phone of the user the admin onboards"),
	"target_role": ("default", "Defaults to Grievance Submitter. Role the admin grants and revokes"),
	"target_user_id": ("default", "Set by Admin > Create User"),
	"temporary_password": ("secret", "Set by Admin > Create User and Issue Temporary Password"),
	"notification_id": ("default", "Set by Notifications > List my notifications"),
}


def script(listen: str, lines: list[str]) -> dict:
	return {"listen": listen, "script": {"type": "text/javascript", "exec": lines}}


def status_test(expected: str, also_ok: tuple[str, str] | None = None) -> list[str]:
	if also_ok:
		code, reason = also_ok
		return [
			f"pm.test('Status code is {expected} (or {code} {reason})', function () {{",
			f"    pm.expect(pm.response.code).to.be.oneOf([{expected}, {code}]);",
			"});",
		]
	return [
		f"pm.test('Status code is {expected}', function () {{",
		f"    pm.response.to.have.status({expected});",
		"});",
		"pm.test('Response is a success envelope', function () {",
		"    pm.response.to.be.json;",
		"    pm.expect(pm.response.json().status).to.eql('success');",
		"});",
	]


def build_url(path: str, query_params: list[dict]) -> dict:
	postman_path = re.sub(r"\{(\w+)\}", lambda m: "{{" + PATH_VARIABLES[m.group(1)] + "}}", path)
	segments = postman_path.strip("/").split("/")
	url = {"raw": "{{base_url}}" + postman_path, "host": ["{{base_url}}"], "path": segments}
	if query_params:
		url["query"] = [
			{
				"key": p["name"],
				"value": QUERY_EXAMPLES.get(p["name"], ""),
				"description": p.get("description", ""),
				"disabled": True,
			}
			for p in query_params
		]
	return url


def build_item(method: str, path: str, op: dict) -> dict:
	key = (method, path)
	success = next(code for code in op["responses"] if code.startswith("2"))
	is_public = op.get("security") == []

	request = {
		"method": method,
		"header": [],
		"url": build_url(path, [p for p in op.get("parameters", []) if p["in"] == "query"]),
		"description": op.get("description") or op.get("summary", ""),
	}
	if is_public:
		request["auth"] = {"type": "noauth"}
	if key in BODIES:
		request["header"].append({"key": "Content-Type", "value": "application/json"})
		request["body"] = {
			"mode": "raw",
			"raw": json.dumps(BODIES[key], indent=4),
			"options": {"raw": {"language": "json"}},
		}

	events = [
		script(
			"test",
			status_test(success, TOLERATED_STATUS.get(key)) + AFTER_RESPONSE.get(key, []),
		)
	]
	if key in PRE_REQUEST:
		events.insert(0, script("prerequest", PRE_REQUEST[key]))

	return {
		"name": op.get("summary", f"{method} {path}").removeprefix("Admin: ").capitalize(),
		"event": events,
		"request": request,
		"response": [],
	}


def build_collection(spec: dict) -> dict:
	order = {key: i for i, key in enumerate(REQUEST_ORDER)}
	folders: dict[str, list[tuple[int, dict]]] = {}
	unordered = []

	for path, methods in spec["paths"].items():
		if path in LEGACY_PATHS:
			continue
		for method, op in methods.items():
			key = (method.upper(), path)
			if key not in order:
				unordered.append(key)
				continue
			tag = op["tags"][0]
			folders.setdefault(tag, []).append((order[key], build_item(key[0], path, op)))

	# Fail rather than silently drop a new route from the collection.
	if unordered:
		raise SystemExit(
			"Routes in the spec with no place in REQUEST_ORDER -- add them and re-run:\n"
			+ "\n".join(f"  {m} {p}" for m, p in unordered)
		)

	tag_descriptions = {t["name"]: t.get("description", "") for t in spec.get("tags", [])}
	tags = sorted(folders, key=lambda t: FOLDER_ORDER.index(t) if t in FOLDER_ORDER else len(FOLDER_ORDER))

	return {
		"info": {
			"_postman_id": COLLECTION_ID,
			"name": spec["info"]["title"],
			"description": (
				f"{spec['info']['description']}\n\n"
				"Generated from openapi/openapi_v1.yaml by postman/generate_postman_collection.py; "
				"do not edit by hand.\n\n"
				"Import oan_auth_environment.json and set base_url, admin_username and admin_password. "
				"Every other variable is generated when blank. Run the collection top to bottom: Register and "
				"Login store the tokens protected requests use; the Admin folder signs in as the admin itself, "
				"and Onboard a user stores target_user_id for the rest. Reset Password is skipped unless "
				"reset_key is set, because that key only arrives by email."
			),
			"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
		"auth": {
			"type": "bearer",
			"bearer": [{"key": "token", "value": "{{access_token}}", "type": "string"}],
		},
		"event": [script("prerequest", DEFAULTS_SCRIPT)],
		"item": [build_folder(tag, tag_descriptions, folders[tag]) for tag in tags],
	}


def build_folder(tag: str, descriptions: dict, entries: list[tuple[int, dict]]) -> dict:
	items = [item for _, item in sorted(entries, key=lambda x: x[0])]
	folder = {"name": tag, "description": descriptions.get(tag, ""), "item": items}
	if tag == "Admin":
		folder["auth"] = ADMIN_AUTH
		folder["item"] = [ADMIN_LOGIN, *items]
	return folder


ADMIN_AUTH = {
	"type": "bearer",
	"bearer": [{"key": "token", "value": "{{admin_access_token}}", "type": "string"}],
}

# The Admin folder signs in on its own, so it works after Register and Login have
# replaced `access_token` with an ordinary user's.
ADMIN_LOGIN = {
	"name": "Sign in as admin",
	"event": [
		script(
			"test",
			[
				*status_test("200"),
				"var data = {}; try { data = pm.response.json().data || {}; } catch (e) {}",
				"if (data.access_token) { pm.environment.set('admin_access_token', data.access_token); }",
			],
		)
	],
	"request": {
		"method": "POST",
		"auth": {"type": "noauth"},
		"header": [{"key": "Content-Type", "value": "application/json"}],
		"body": {
			"mode": "raw",
			"raw": json.dumps({"usr": "{{admin_username}}", "pwd": "{{admin_password}}"}, indent=4),
			"options": {"raw": {"language": "json"}},
		},
		"url": {
			"raw": "{{base_url}}/api/v1/auth/login",
			"host": ["{{base_url}}"],
			"path": ["api", "v1", "auth", "login"],
		},
		"description": "Signs in with admin_username / admin_password (a System Manager) and stores admin_access_token, which every request in this folder uses.",
	},
	"response": [],
}

# Runs before every request: fill any variable the user left blank with a value
# that works. Only blanks are filled, so anything typed in is kept.
DEFAULTS_SCRIPT = [
	"var rand = Math.random().toString(36).slice(2, 8);",
	"function fallback(key, value) { if (!pm.environment.get(key)) { pm.environment.set(key, value); } }",
	"fallback('user_email', 'pm_user_' + rand + '@example.com');",
	"fallback('user_password', 'Passw0rd!' + rand);",
	"fallback('user_new_password', 'NewPassw0rd!' + rand);",
	"fallback('user_full_name', 'Postman User');",
	"fallback('user_phone_number', '+2519' + Math.floor(10000000 + Math.random() * 89999999));",
	"fallback('target_email', 'pm_target_' + rand + '@example.com');",
	"fallback('target_role', 'Grievance Submitter');",
	"fallback('target_phone_number', '+2519' + Math.floor(10000000 + Math.random() * 89999999));",
	"fallback('user_fayda_id', String(Math.floor(1e15 + Math.random() * 9e15)));",
	"fallback('target_fayda_id', String(Math.floor(1e15 + Math.random() * 9e15)));",
]

# A fresh value per run for anything that must be unique, so a second run does not
# fail on a duplicate. Values the user typed are left alone: only blanks and
# values this script generated (`pm_` email, `+2519` phone) are replaced.
FRESH_USER = [
	"var rand = Math.random().toString(36).slice(2, 8);",
	"function fresh(key, prefix, value) { var cur = pm.environment.get(key); if (!cur || String(cur).indexOf(prefix) === 0) { pm.environment.set(key, value); } }",
	"fresh('user_email', 'pm_', 'pm_user_' + rand + '@example.com');",
	"fresh('user_phone_number', '+2519', '+2519' + Math.floor(10000000 + Math.random() * 89999999));",
	"pm.environment.set('user_fayda_id', String(Math.floor(1e15 + Math.random() * 9e15)));",
]

FRESH_TARGET = [
	"pm.environment.set('target_phone_number', '+2519' + Math.floor(10000000 + Math.random() * 89999999));",
	"pm.environment.set('target_fayda_id', String(Math.floor(1e15 + Math.random() * 9e15)));",
	"var cur = pm.environment.get('target_email');",
	"if (!cur || String(cur).indexOf('pm_') === 0) { pm.environment.set('target_email', 'pm_target_' + Math.random().toString(36).slice(2, 8) + '@example.com'); }",
]

# Needs a key that only arrives by email, so it cannot run unattended.
SKIP_WITHOUT_RESET_KEY = [
	"if (!pm.environment.get('reset_key')) {",
	"    console.log('reset_key is empty: the reset link is emailed, so this request is skipped.');",
	"    pm.execution.skipRequest();",
	"}",
]

# Answers that depend on how the site is set up rather than on the API: the reset
# link is mailed, and a site with no outgoing email account answers 501.
TOLERATED_STATUS = {
	("POST", "/api/v1/auth/password/forgot"): ("501", "when the site has no outgoing email"),
}

PRE_REQUEST = {
	("POST", "/api/v1/auth/register"): FRESH_USER,
	("POST", "/api/v1/admin/users"): FRESH_TARGET,
	("POST", "/api/v1/auth/password/reset"): SKIP_WITHOUT_RESET_KEY,
}


def update_environment() -> None:
	"""Add any variable the collection uses to the environment, keeping existing values."""
	env = json.loads(ENVIRONMENT_PATH.read_text())
	existing = {v["key"]: v for v in env["values"]}
	env["values"] = [
		{
			"key": name,
			"value": existing.get(name, {}).get("value", ""),
			"type": kind,
			"enabled": True,
			"description": note,
		}
		for name, (kind, note) in VARIABLES.items()
	]
	ENVIRONMENT_PATH.write_text(json.dumps(env, indent="\t") + "\n")


def main() -> None:
	spec = yaml.safe_load(SPEC_PATH.read_text())
	collection = build_collection(spec)
	COLLECTION_PATH.write_text(json.dumps(collection, indent="\t") + "\n")
	update_environment()

	n = sum(len(f["item"]) for f in collection["item"])
	sys.stderr.write(
		f"Wrote {COLLECTION_PATH.name}: {n} requests in {len(collection['item'])} folders; "
		f"{ENVIRONMENT_PATH.name}: {len(VARIABLES)} variables\n"
	)


if __name__ == "__main__":
	main()
