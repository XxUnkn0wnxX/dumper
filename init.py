#!/usr/bin/env python3
"""Prepare or check the dumper's Python environment without device operations."""

import argparse
import sys

from Helpers.Bootstrap import BootstrapError, initialize_environment
from Helpers.CLI import ignore_interrupts, prepare_terminal


# ------------------------------------------------------------------------------
# ENVIRONMENT INITIALIZATION ONLY
# The shared helper respects an active custom venv, or creates/reuses .venv.
# This entry point does not import Frida, connect to Android, or run a tool.
# ------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Ensure project requirements and report dependency health, then exit."""
    try:
        prepare_terminal()
        parser = argparse.ArgumentParser(description=__doc__)
        parser.parse_args(argv)
        interpreter = initialize_environment()
        print(f'Python setup is ready: {interpreter}', flush=True)
        print('Project requirements and pip check passed.', flush=True)
        return 0
    except (BootstrapError, OSError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        with ignore_interrupts():
            print('\nInitialization cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
