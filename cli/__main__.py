"""Package entry‑point so `python -m cli ...` works.
Simply proxies to the Click root command defined in `cli.py`."""

from .cli import cli

if __name__ == "__main__":
    # Delegate to Click's CLI group
    cli()
