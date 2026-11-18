"""Add `User.da_registry_id` to sites that already have this app installed.

Fresh sites get the field from the `after_install` hook instead — see
`oan_auth_service/setup/install.py` for why both entry points exist. Sites that
already have it (created earlier by da_services) are left as they are.
"""

from oan_auth_service.setup.install import create_da_registry_id_field


def execute():
	create_da_registry_id_field()
