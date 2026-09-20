#!/usr/bin/env python3
"""Optionally rebuild the shipped protobuf binding and its exact runtime pin."""

import argparse
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

if __package__ in (None, ''):
    # Direct ``python tools/regenerate_protobuf.py`` has ``tools/`` as its
    # first import location. Add the repository root so the shared CLI helper
    # remains available from any caller directory.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Helpers.CLI import defer_interrupts, ignore_interrupts, prepare_terminal
from Helpers.Bootstrap import BootstrapError, bootstrap


# ------------------------------------------------------------------------------
# REPOSITORY PATHS
# Resolve from this file so maintainers can invoke the helper from any directory.
# Generated files are staged under the repository's ignored .tmp/ directory.
# ------------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = Path('Helpers/wv_proto2.proto')
BINDING = Path('Helpers/wv_proto2_pb2.py')
REQUIREMENTS = Path('requirements.txt')


class RegenerationError(RuntimeError):
    """A compiler, runtime, or output validation step failed."""


def run_command(command, purpose):
    try:
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RegenerationError(f'{purpose}: {error}') from error
    if result.returncode:
        detail = (result.stdout + result.stderr).strip()
        raise RegenerationError(f'{purpose} failed (exit {result.returncode}):\n{detail}')
    return result.stdout.strip()


# ------------------------------------------------------------------------------
# RUNTIME PIN
# The generated Python version is authoritative: protoc's version number uses a
# different numbering scheme. Preserve every unrelated requirement and newline.
# ------------------------------------------------------------------------------
def runtime_pin(generated):
    match = re.search(
        rb'^# Protobuf Python Version: (\d+\.\d+\.\d+)\r?$', generated, re.MULTILINE,
    )
    if not match:
        raise RegenerationError('Generated output has no stable Protobuf Python version header.')
    return 'protobuf==' + match.group(1).decode('ascii')


def update_requirement(original, pin):
    lines = original.decode('utf-8').splitlines(keepends=True)
    matches = 0
    for index, line in enumerate(lines):
        body = line.rstrip('\r\n')
        if re.fullmatch(r'protobuf(?:\s*[<>=!~].*)?\s*', body, re.IGNORECASE):
            lines[index] = pin + line[len(body):]
            matches += 1
    if matches != 1:
        raise RegenerationError('Expected exactly one protobuf entry in requirements.txt.')
    return ''.join(lines).encode('utf-8')


# ------------------------------------------------------------------------------
# OUTPUT REPLACEMENT
# Validate both outputs first. Use replacements on the same filesystem, preserve
# file permissions, and restore already-replaced files if a later write fails.
# ------------------------------------------------------------------------------
def replace_outputs(outputs, staging):
    originals = {}
    staged = {}
    for index, (relative, content) in enumerate(outputs.items()):
        target = ROOT / relative
        originals[target] = target.read_bytes() if target.exists() else None
        mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o644
        pending = staging / f'replacement-{index}'
        pending.write_bytes(content)
        pending.chmod(mode)
        staged[target] = (pending, mode)

    replaced = []
    try:
        for target, (pending, _) in staged.items():
            # Register before the atomic rename. If Ctrl+C arrives immediately
            # after replace(), rollback still knows this target may have been
            # changed and can restore it safely.
            replaced.append(target)
            pending.replace(target)
    except (OSError, KeyboardInterrupt) as error:
        recovery_errors = []
        # A second Ctrl+C must not interrupt restoration of tracked files.
        with ignore_interrupts():
            for index, target in enumerate(reversed(replaced)):
                try:
                    if originals[target] is None:
                        try:
                            target.unlink()
                        except FileNotFoundError:
                            pass
                    else:
                        restore = staging / f'restore-{index}'
                        restore.write_bytes(originals[target])
                        restore.chmod(staged[target][1])
                        restore.replace(target)
                except OSError as recovery_error:
                    recovery_errors.append(f'{target.name}: {recovery_error}')
        if isinstance(error, KeyboardInterrupt):
            if recovery_errors:
                with ignore_interrupts():
                    print(
                        'Warning: cancellation interrupted output replacement and '
                        'rollback did not fully restore the previous files: '
                        + '; '.join(recovery_errors),
                        file=sys.stderr,
                    )
            raise
        detail = '; '.join(recovery_errors) or 'Previous output files restored.'
        raise RegenerationError(f'Could not replace outputs: {error}. {detail}') from error


def _run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protoc', default='protoc', help='Compiler executable or path (default: protoc).')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Check generated output and pin without replacing them.')
    mode.add_argument('--update-runtime', action='store_true', help='Install the generated build\'s exact protobuf version into this virtual environment.')
    args = parser.parse_args()
    if args.update_runtime and sys.prefix == sys.base_prefix:
        parser.error('--update-runtime requires a virtual environment; use .venv/bin/python.')

    try:
        compiler = run_command([args.protoc, '--version'], 'Locating protoc')
        original_requirements = (ROOT / REQUIREMENTS).read_bytes()
        (ROOT / '.tmp').mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='protobuf-', dir=ROOT / '.tmp')
        try:
            staging = Path(temporary.name)
            run_command([
                args.protoc, '--proto_path=.', f'--python_out={staging}', str(SCHEMA),
            ], 'Generating Python bindings')
            generated_path = staging / BINDING
            generated = generated_path.read_bytes()
            pin = runtime_pin(generated)
            requirements = update_requirement(original_requirements, pin)
            print(f'{compiler}: generated binding requires {pin}', flush=True)

            # Environment updates are explicit and affect only protobuf. A failed
            # later check leaves tracked files intact, but does not undo pip changes.
            if args.update_runtime:
                run_command([sys.executable, '-m', 'pip', 'install', '--upgrade', pin], 'Updating protobuf runtime')
            run_command([
                sys.executable, '-I', '-c',
                'import runpy, sys; runpy.run_path(sys.argv[1])', str(generated_path),
            ], 'Validating generated import (use --update-runtime if the runtime is incompatible)')

            outputs = {BINDING: generated, REQUIREMENTS: requirements}
            changed = {path: data for path, data in outputs.items()
                       if not (ROOT / path).exists() or (ROOT / path).read_bytes() != data}
            if args.check:
                if changed:
                    print('Out of date: ' + ', '.join(str(path) for path in changed), file=sys.stderr)
                    return 1
                print('Generated binding and runtime pin are current.')
            elif changed:
                replace_outputs(changed, staging)
                print('Updated: ' + ', '.join(str(path) for path in changed))
            else:
                print('Generated binding and runtime pin are already current.')
        finally:
            # TemporaryDirectory's normal __exit__ is vulnerable to a second
            # terminal interrupt while removing a partially generated tree.
            cleanup_active_exception = sys.exc_info()[0] is not None
            try:
                with defer_interrupts():
                    temporary.cleanup()
            except OSError as cleanup_error:
                with ignore_interrupts():
                    print(
                        f'Warning: could not clean temporary protobuf staging: {cleanup_error}',
                        file=sys.stderr,
                    )
                if not cleanup_active_exception:
                    raise RegenerationError(
                        f'Could not clean temporary protobuf staging: {cleanup_error}'
                    ) from cleanup_error
    except (RegenerationError, OSError, UnicodeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    return 0


def main():
    """Run regeneration and turn every user cancellation into status 130."""
    try:
        # Install terminal handling before argparse so Ctrl+C during parsing or
        # version validation follows the same clean cancellation path.
        prepare_terminal()
        if __name__ == '__main__':
            bootstrap(Path(__file__))
        return _run()
    except BootstrapError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        with ignore_interrupts():
            print('\nCancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
