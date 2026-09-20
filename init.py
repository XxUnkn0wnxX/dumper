#!/usr/bin/env python3
"""Create, check, or repair the separate dumper and WVD Python environments."""

import argparse
import sys

from Helpers.Bootstrap import BootstrapError, display_path
from Helpers.CLI import ignore_interrupts, prepare_terminal
from Helpers.WvdBootstrap import initialize_project_environments


# ------------------------------------------------------------------------------
# ENVIRONMENT INITIALIZATION ONLY
# The shared helpers respect an active custom main venv, or create/reuse .venv,
# and always prepare the isolated .venv-wvd environment for WVD tooling.
# This entry point does not import Frida, connect to Android, or run a tool.
# ------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Ensure both project environments and report dependency health, then exit."""
    try:
        prepare_terminal()
        parser = argparse.ArgumentParser(description=__doc__)
        parser.parse_args(argv)
        main_interpreter, wvd_interpreter = initialize_project_environments()
        print(f'Main Python setup is ready: {display_path(main_interpreter)}', flush=True)
        print(f'WVD Python setup is ready: {display_path(wvd_interpreter)}', flush=True)
        print('Project and WVD requirements and pip checks passed.', flush=True)
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
