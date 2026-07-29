"""Compatibility shim for the installed authoritative PPF CLI."""

from __future__ import annotations

import sys

from ppf.cli import main


if __name__ == "__main__":
    sys.exit(main())
