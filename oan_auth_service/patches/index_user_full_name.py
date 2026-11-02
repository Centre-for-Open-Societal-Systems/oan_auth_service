"""Index `User.full_name` on sites that already have this app installed.

Fresh sites get it from the `after_install` hook; see `oan_auth_service/setup/install.py`.
"""

from oan_auth_service.setup.install import index_user_full_name


def execute():
	index_user_full_name()
