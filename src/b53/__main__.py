"""Allow ``python -m b53`` execution."""

from __future__ import annotations

from b53.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
