"""Standard (DocType JSON) and live (Custom DocPerm) permission rules, and drift between them."""

import frappe
from frappe.permissions import rights as RIGHTS

from oan_auth_service.config import settings


def _key(rule) -> tuple[str, int, int]:
	return rule.role, int(rule.permlevel or 0), int(rule.if_owner or 0)


def _rights(rule) -> dict[str, int]:
	return {p: int(rule.get(p) or 0) for p in RIGHTS}


def has_custom_rules(doctype: str) -> bool:
	return bool(frappe.db.exists("Custom DocPerm", {"parent": doctype}))


def rule_rows(doctype: str, roles: set[str] | None = None) -> list[dict]:
	"""Rules of `doctype`, limited to `roles` when given, with their source and drift."""
	standard = {_key(r): r for r in frappe.get_all("DocPerm", filters={"parent": doctype}, fields="*")}
	custom = has_custom_rules(doctype)
	live = (
		{_key(r): r for r in frappe.get_all("Custom DocPerm", filters={"parent": doctype}, fields="*")}
		if custom
		else standard
	)

	rows = []
	for key in sorted(set(live) | (set(standard) if custom else set())):
		role, permlevel, if_owner = key
		if roles is not None and role not in roles:
			continue
		rule = live.get(key) or standard[key]
		active = key in live
		std = standard.get(key)
		rows.append(
			{
				"doctype": doctype,
				"role": role,
				"permlevel": permlevel,
				"if_owner": bool(if_owner),
				**_rights(rule),
				"source": "custom" if custom else "standard",
				"active": active,
				"differs_from_standard": custom
				and (not active or std is None or _rights(rule) != _rights(std)),
			}
		)
	return rows


def drifted_rules(doctype: str) -> list[dict]:
	"""Rules of `doctype` whose live form differs from its DocType JSON."""
	if not has_custom_rules(doctype):
		return []
	return [r for r in rule_rows(doctype) if r["differs_from_standard"]]


def warn_permission_drift() -> None:
	"""Print and log service DocTypes whose custom rules differ from their DocType JSON."""
	prefixes = settings.service_prefixes()
	if not prefixes:
		return
	doctypes = sorted(
		{
			d.parent
			for d in frappe.get_all("Custom DocPerm", fields=["parent"], distinct=True)
			if settings.name_in_scope(d.parent, prefixes)
		}
	)
	for doctype in doctypes:
		if drift := drifted_rules(doctype):
			rules = ", ".join(f"{r['role']} (level {r['permlevel']})" for r in drift)
			message = (
				f"Permission drift on {doctype}: custom rules differ from the DocType JSON for {rules}. "
				"JSON permission changes do not apply until the custom rules are reset or patched."
			)
			print(message)
			frappe.logger().warning(message)
