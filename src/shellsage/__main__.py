"""Allow ``python -m shellsage``."""

import sys

from shellsage.cli import main

if __name__ == "__main__":
    sys.exit(main())
