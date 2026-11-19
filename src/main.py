#!/usr/bin/env python3
"""Backwards-compatible launcher.

ShellSage 0.x was a single script that people wired into their shell as
``python3 ~/shell-sage/src/main.py``. The code now lives in the ``shellsage``
package next to this file; this shim keeps the old alias working without an
install step. New setups should ``pip install .`` and use the ``sage`` command.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shellsage.cli import main

if __name__ == "__main__":
    sys.exit(main())
