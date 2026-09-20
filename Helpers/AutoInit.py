"""Full-auto's background environment initialization, logged to logs/init.log."""

from pathlib import Path
import os
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Helpers.AutoSession import AutoSessionError, emit_event
from Helpers.Bootstrap import BootstrapError, bootstrap
from Helpers.CLI import ignore_interrupts, prepare_terminal


def main():
    try:
        prepare_terminal()
        # Reuse the public initializer and its shared bootstrap. Once relaunch
        # completes, package discovery and all later children use this venv.
        bootstrap(Path(__file__))
        from init import main as initialize
        result = initialize([])
        if result:
            return result
        from tools.setup_frida import SetupError, resolve_adb
        try:
            adb = resolve_adb(os.environ.get('DUMPER_AUTO_ADB') or None)
        except SetupError as error:
            print(f'error: {error}', file=sys.stderr, flush=True)
            return 1
        emit_event('environment_ready', python=sys.executable, adb=adb)
        return 0
    except (BootstrapError, AutoSessionError, OSError) as error:
        print(f'error: {error}', file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        with ignore_interrupts():
            print('\nInitialization cancelled.', file=sys.stderr, flush=True)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
