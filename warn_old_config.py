# pylint: disable=unused-import
# ruff: noqa: F401, E722

import sys

try:
    from config import SDM_MASTER_KEY  # type: ignore
except ImportError:
    # this is ok
    pass
else:
    print("WARNING! Detected SDM_MASTER_KEY configuration variable. "
          "This refers to the obsolete key derivation algorithm. If you are relying on the"
          "old algorithm, please downgrade sdm-backend to older version.")
    sys.exit(1)
