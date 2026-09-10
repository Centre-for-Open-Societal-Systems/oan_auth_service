"""Versioned public API for the Authentication and User Management module."""

CURRENT_VERSION = "v1"

# Version registry. `status` is one of: current, deprecated, sunset.
VERSIONS = {
	"v1": {
		"status": "current",
		"released_on": "2026-09-01",
		"sunset_on": None,
		"notes": "First public contract for authentication and token management.",
	},
}


def version_meta(version: str = CURRENT_VERSION) -> dict:
	"""Return the standard `meta` dictionary every API response carries."""
	info = VERSIONS.get(version, {})
	meta = {"api_version": version, "status": info.get("status", "current")}
	if info.get("sunset_on"):
		meta["sunset_on"] = info["sunset_on"]
	return meta
