"""Add `User.oan_must_change_password` to sites that already have this app installed.

Fresh sites get the field from the `after_install` hook instead — see
`oan_auth_service/setup/install.py` for why both entry points exist.
"""

from oan_auth_service.setup.install import create_must_change_password_field


def execute():
	create_must_change_password_field()
