"""Turn on change tracking for Custom DocPerm on sites that already have this app installed."""

from oan_auth_service.setup.install import enable_custom_docperm_tracking


def execute():
	enable_custom_docperm_tracking()
