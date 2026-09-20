"""Standard-library virtual-environment bootstrap shared by repository CLIs.

Normal command entry points call :func:`bootstrap` before importing optional
dependencies.  It relaunches an interpreter started outside a virtual
environment through this repository's ``.venv``.  An already-active real venv
is deliberately left alone: it may be a maintained environment with a
different name or location.

``init.py`` uses :func:`initialize_environment` directly.  That explicit setup
command validates the active venv when there is one, otherwise the repository
``.venv``, and repairs missing root requirements through a preflighted set that
keeps unrelated installed packages at their current exact versions.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence

from Helpers.CLI import defer_interrupts, ignore_interrupts
from Helpers.AutoLogging import log_captured_output, run_logged_subprocess


ROOT = Path(__file__).resolve().parents[1]
VENV_NAME = '.venv'
VENV_TIMEOUT = 120
PROBE_TIMEOUT = 30
PIP_INSTALL_TIMEOUT = 300
PIP_CHECK_TIMEOUT = 60
WINDOWS_RELAUNCH_INTERRUPT_GRACE = 15
WINDOWS_RELAUNCH_REAP_TIMEOUT = 5

_PACKAGE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z')
_PACKAGE_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.!+_-]*\Z')
_PLATFORM_MACHINE = re.compile(r'[A-Za-z0-9._-]+\Z')
_PLATFORM_MACHINE_MARKER = re.compile(
    r'platform_machine\s*==\s*([\'"])([A-Za-z0-9._-]+)\1\Z'
)

# These variables can send an install somewhere other than the selected venv,
# add requirements outside requirements.txt, or weaken the resolver.  Network,
# index, proxy, and certificate variables are intentionally not in this list.
_REJECTED_PIP_ENVIRONMENT = {
    'PIP_TARGET': 'redirects the installation target',
    'PIP_PREFIX': 'redirects the installation prefix',
    'PIP_ROOT': 'redirects the installation root',
    'PIP_USER': 'redirects to the user site',
    'PIP_PYTHON': 'selects a different Python interpreter',
    'PIP_NO_DEPS': 'disables dependency resolution',
    'PIP_USE_DEPRECATED': 'can select the legacy resolver',
    'PIP_REQUIREMENT': 'adds requirements outside requirements.txt',
    'PIP_CONSTRAINT': 'adds constraints outside requirements.txt',
    'PIP_EDITABLE': 'adds editable requirements outside requirements.txt',
    'PIP_GLOBAL_OPTION': 'adds package build options outside requirements.txt',
    'PIP_INSTALL_OPTION': 'adds package install options outside requirements.txt',
    'PIP_UPGRADE': 'changes the requested no-upgrade install policy',
    'PIP_FORCE_REINSTALL': 'forces package replacement',
    'PIP_IGNORE_INSTALLED': 'ignores installed packages',
}


class BootstrapError(RuntimeError):
    """The repository virtual environment cannot be safely initialized."""


@dataclass(frozen=True)
class Requirement:
    """One intentionally limited, index-based root requirement."""

    name: str
    version: str | None
    platform_machines: tuple[str, ...] | None = None
    source: str | None = None

    @property
    def normalized_name(self) -> str:
        return re.sub(r'[-_.]+', '-', self.name).lower()

    @property
    def pip_requirement(self) -> str:
        if self.source is not None:
            return self.source
        return self.name if self.version is None else f'{self.name}=={self.version}'


@dataclass(frozen=True)
class RootRequirements:
    """The supported root package requirements and wheel-selection options."""

    requirements: tuple[Requirement, ...]
    pip_options: tuple[str, ...]


def _parse_platform_machine_marker(marker: str, *, requirements_file: Path,
                                   line_number: int, original: str) -> tuple[str, ...]:
    """Accept only platform_machine equality terms joined by lowercase ``or``."""
    terms = re.split(r'\s+or\s+', marker.strip())
    machines = []
    for term in terms:
        match = _PLATFORM_MACHINE_MARKER.fullmatch(term)
        if match is None or not _PLATFORM_MACHINE.fullmatch(match.group(2)):
            raise BootstrapError(
                f'Unsupported platform marker at {requirements_file}:{line_number}: {original!r}. '
                'Automatic setup accepts only platform_machine == "value" terms joined by or.'
            )
        machines.append(match.group(2))
    if not machines:
        raise BootstrapError(
            f'Unsupported platform marker at {requirements_file}:{line_number}: {original!r}.'
        )
    return tuple(machines)


def running_in_virtual_environment() -> bool:
    """Return whether this interpreter is a real venv, not a shell hint.

    ``real_prefix`` covers legacy virtualenv installations.  In particular,
    this does not inspect ``VIRTUAL_ENV``: a stale activation variable must not
    prevent normal repository setup.
    """
    base_prefix = getattr(sys, 'base_prefix', sys.prefix)
    real_prefix = getattr(sys, 'real_prefix', None)
    return sys.prefix != base_prefix or (
        real_prefix is not None and sys.prefix != real_prefix
    )


def _requirements_path() -> Path:
    return ROOT / 'requirements.txt'


def _repository_venv() -> Path:
    return ROOT / VENV_NAME


def _is_windows() -> bool:
    """Keep platform selection mockable without changing pathlib's platform."""
    return os.name == 'nt'


def _venv_python(venv: Path) -> Path:
    if _is_windows():
        return venv / 'Scripts' / 'python.exe'
    return venv / 'bin' / 'python'


def _command_error(purpose: str, result: subprocess.CompletedProcess) -> BootstrapError:
    detail = ((getattr(result, 'stdout', None) or '') + (getattr(result, 'stderr', None) or '')).strip()
    if len(detail) > 12000 and os.environ.get('DUMPER_AUTO_LOGGING') != '1':
        detail = f'{detail[:12000]}\n... output truncated'
    suffix = f': {detail}' if detail else ''
    return BootstrapError(f'{purpose} failed (exit {result.returncode}){suffix}')


def _run_command(command: Sequence[str], purpose: str, *, timeout: int,
                 environment: dict[str, str] | None = None,
                 capture_output: bool = True) -> subprocess.CompletedProcess:
    """Run one bounded local command with a concise, contextual failure."""
    try:
        result = run_logged_subprocess(
            list(command),
            text=True,
            capture_output=capture_output,
            timeout=timeout,
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        log_captured_output(error)
        raise BootstrapError(
            f'{purpose} timed out after {timeout} seconds. Check the Python environment or network, then retry.'
        ) from error
    except OSError as error:
        raise BootstrapError(f'{purpose} could not start: {error}') from error
    log_captured_output(result)
    if result.returncode:
        raise _command_error(purpose, result)
    return result


def _read_requirements() -> RootRequirements:
    """Read only approved root package syntax and wheel-selection metadata."""
    requirements_file = _requirements_path()
    try:
        lines = requirements_file.read_text(encoding='utf-8').splitlines()
    except OSError as error:
        raise BootstrapError(f'Cannot read root requirements file {requirements_file}: {error}') from error

    requirements: list[Requirement] = []
    pip_options: list[str] = []
    seen: set[str] = set()
    for number, original in enumerate(lines, start=1):
        line = original.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('--only-binary='):
            values = line.removeprefix('--only-binary=').split(',')
            if not values or any(not _PACKAGE_NAME.fullmatch(value) for value in values):
                raise BootstrapError(
                    f'Unsupported --only-binary value at {requirements_file}:{number}: {original!r}. '
                    'Automatic setup accepts one or more comma-separated package names.'
                )
            pip_options.append(line)
            continue
        requirement_text, marker_separator, marker = line.partition(';')
        platform_machines = None
        if marker_separator:
            platform_machines = _parse_platform_machine_marker(
                marker, requirements_file=requirements_file, line_number=number, original=original,
            )
        name, separator, version = requirement_text.strip().partition('==')
        if not _PACKAGE_NAME.fullmatch(name) or (
            separator and not _PACKAGE_VERSION.fullmatch(version)
        ):
            raise BootstrapError(
                f'Unsupported requirement at {requirements_file}:{number}: {original!r}. '
                'Automatic setup accepts only plain package names, exact name==version pins, '
                'or --only-binary=package[,package].'
            )
        requirement = Requirement(
            name, version if separator else None, platform_machines=platform_machines, source=line,
        )
        if requirement.normalized_name in seen:
            raise BootstrapError(
                f'Duplicate requirement {name!r} at {requirements_file}:{number}; '
                'automatic setup will not guess which entry should win.'
            )
        seen.add(requirement.normalized_name)
        requirements.append(requirement)
    if not requirements:
        raise BootstrapError(f'Root requirements file {requirements_file} has no installable packages.')
    return RootRequirements(tuple(requirements), tuple(pip_options))


def _pip_environment() -> dict[str, str]:
    """Return an install environment that ignores user pip config files.

    Index/proxy/certificate variables remain inherited.  Variables that can
    redirect, expand, or weaken this fixed requirements install are rejected
    instead of silently changed.
    """
    rejected = [
        f'{name} ({_REJECTED_PIP_ENVIRONMENT[name]})'
        for name in _REJECTED_PIP_ENVIRONMENT if name in os.environ
    ]
    if rejected:
        raise BootstrapError(
            'Automatic dependency installation refuses pip environment settings: '
            f'{", ".join(sorted(rejected))}. Unset them and retry.'
        )
    environment = os.environ.copy()
    # /dev/null is recognized by pip as an explicit request to skip config
    # loading.  os.devnull provides the Windows equivalent too.
    environment['PIP_CONFIG_FILE'] = os.devnull
    return environment


def _fresh_venv_report(python: Path, *, expected_prefix: Path | None) -> None:
    """Prove a selected interpreter starts in a real venv in isolated mode."""
    script = (
        'import json, sys\n'
        'print(json.dumps({"prefix": sys.prefix, "base_prefix": '
        'getattr(sys, "base_prefix", sys.prefix), "real_prefix": '
        'getattr(sys, "real_prefix", None)}))\n'
    )
    result = _run_command(
        [str(python), '-I', '-c', script],
        f'Checking virtual-environment interpreter {python}',
        timeout=PROBE_TIMEOUT,
    )
    try:
        report = json.loads((result.stdout or '').strip().splitlines()[-1])
        prefix = report['prefix']
        base_prefix = report['base_prefix']
        real_prefix = report['real_prefix']
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise BootstrapError(
            f'Virtual-environment interpreter {python} returned an unreadable prefix report.'
        ) from error
    is_venv = (
        isinstance(prefix, str)
        and isinstance(base_prefix, str)
        and (
            prefix != base_prefix
            or (isinstance(real_prefix, str) and prefix != real_prefix)
        )
    )
    if not is_venv:
        raise BootstrapError(
            f'Virtual-environment interpreter {python} does not report a distinct venv prefix.'
        )
    if expected_prefix is not None:
        try:
            actual = Path(prefix).resolve()
            expected = expected_prefix.resolve()
        except OSError as error:
            raise BootstrapError(f'Could not resolve repository virtual-environment prefix: {error}') from error
        if actual != expected:
            raise BootstrapError(
                f'Repository virtual environment {expected_prefix} uses an interpreter whose sys.prefix is {prefix}; '
                'it was not changed. Repair or recreate that .venv manually.'
            )


def _installed_requirements(python: Path, requirements: Iterable[Requirement]) -> tuple[dict[str, str | None | bool], str]:
    """Read selected metadata and evaluate narrow platform markers in that venv."""
    requested = [
        {'name': requirement.name, 'platform_machines': requirement.platform_machines}
        for requirement in requirements
    ]
    script = (
        'import json, platform, sys\n'
        'from importlib import metadata\n'
        'requirements = json.loads(sys.argv[1])\n'
        'machine = platform.machine()\n'
        'installed = {}\n'
        'for requirement in requirements:\n'
        '    name = requirement["name"]\n'
        '    machines = requirement["platform_machines"]\n'
        '    if machines is not None and machine not in machines:\n'
        '        installed[name] = False\n'
        '        continue\n'
        '    try:\n'
        '        installed[name] = metadata.version(name)\n'
        '    except metadata.PackageNotFoundError:\n'
        '        installed[name] = None\n'
        'print(json.dumps({"machine": machine, "installed": installed}, sort_keys=True))\n'
    )
    result = _run_command(
        [str(python), '-I', '-c', script, json.dumps(requested)],
        f'Checking installed requirements with {python}',
        timeout=PROBE_TIMEOUT,
    )
    try:
        report = json.loads((result.stdout or '').strip().splitlines()[-1])
        machine = report['machine']
        installed = report['installed']
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise BootstrapError(f'Requirements check through {python} returned an unreadable metadata report.') from error
    if not isinstance(installed, dict) or any(
        not isinstance(name, str) or not (isinstance(version, str) or version is None or version is False)
        for name, version in installed.items()
    ):
        raise BootstrapError(f'Requirements check through {python} returned invalid metadata fields.')
    if not isinstance(machine, str) or not _PLATFORM_MACHINE.fullmatch(machine):
        raise BootstrapError(f'Requirements check through {python} returned an invalid platform machine value.')
    return {requirement.name: installed.get(requirement.name) for requirement in requirements}, machine


def _installed_distributions(python: Path) -> tuple[Requirement, ...]:
    """Read every installed distribution in a fresh isolated interpreter.

    The package names and versions become exact temporary requirements before a
    root-requirements repair.  Do not use a host ``pip freeze`` here: its
    interpreter or configuration may differ from the selected virtualenv.
    """
    script = (
        'import json\n'
        'from importlib import metadata\n'
        'print(json.dumps([\n'
        '    [distribution.metadata.get("Name"), distribution.version]\n'
        '    for distribution in metadata.distributions()\n'
        ']))\n'
    )
    result = _run_command(
        [str(python), '-I', '-c', script],
        f'Reading installed distributions with {python}',
        timeout=PROBE_TIMEOUT,
    )
    try:
        records = json.loads((result.stdout or '').strip().splitlines()[-1])
    except (IndexError, TypeError, json.JSONDecodeError) as error:
        raise BootstrapError(f'Installed-distribution check through {python} returned an unreadable report.') from error
    if not isinstance(records, list):
        raise BootstrapError(f'Installed-distribution check through {python} returned invalid metadata fields.')

    distributions: dict[str, Requirement] = {}
    for record in records:
        if not isinstance(record, list) or len(record) != 2:
            raise BootstrapError(f'Installed-distribution check through {python} returned an invalid record.')
        name, version = record
        if not isinstance(name, str) or not _PACKAGE_NAME.fullmatch(name):
            raise BootstrapError(
                'An installed Python distribution has an unsafe or missing name; '
                'refuse to construct temporary requirements from local metadata.'
            )
        if not isinstance(version, str) or not _PACKAGE_VERSION.fullmatch(version):
            raise BootstrapError(
                f'Installed Python distribution {name!r} has an unsafe version; '
                'refuse to construct temporary requirements from local metadata.'
            )
        requirement = Requirement(name, version)
        previous = distributions.get(requirement.normalized_name)
        if previous is not None and previous != requirement:
            raise BootstrapError(
                f'Installed Python metadata has conflicting entries for {name!r}; '
                'refuse to change the environment automatically.'
            )
        distributions[requirement.normalized_name] = requirement
    return tuple(distributions[name] for name in sorted(distributions))


def _missing_or_wrong_requirements(requirements: Iterable[Requirement],
                                   installed: dict[str, str | None | bool]) -> list[str]:
    missing = []
    for requirement in requirements:
        version = installed.get(requirement.name)
        if version is False:
            continue
        if version is None:
            missing.append(requirement.name)
        elif requirement.version is not None and version != requirement.version:
            missing.append(f'{requirement.name}=={requirement.version} (found {version})')
    return missing


def _pip_check(python: Path, *, context: str, environment: dict[str, str] | None = None) -> None:
    """Stop before handoff when pip reports a broken dependency graph."""
    try:
        _run_command(
            [str(python), '-I', '-m', 'pip', 'check'],
            f'Checking dependencies in {context}',
            timeout=PIP_CHECK_TIMEOUT,
            environment=environment,
        )
    except BootstrapError as error:
        raise BootstrapError(f'Dependency check for {context} failed. {error}') from error


def _complete_requested_requirements(root: RootRequirements, installed: Iterable[Requirement],
                                    *, target_machine: str) -> tuple[str, ...]:
    """Pin non-root packages and append the exact project request.

    Root packages remain expressed exactly as ``requirements.txt`` does.  In
    particular, an already compatible unpinned Frida installation remains the
    selected version because pip receives no ``--upgrade`` request.
    """
    active_root_names = {
        requirement.normalized_name
        for requirement in root.requirements
        if requirement.platform_machines is None or target_machine in requirement.platform_machines
    }
    pinned = [
        requirement.pip_requirement for requirement in installed
        if requirement.normalized_name not in active_root_names
    ]
    return tuple([*root.pip_options, *pinned, *(item.pip_requirement for item in root.requirements)])


def _pip_install_command(python: Path, requirements_file: Path, *, dry_run: bool) -> list[str]:
    """Build the same bounded, virtualenv-only resolver command for both passes."""
    command = [
        str(python), '-I', '-m', 'pip', 'install',
        '--require-virtualenv', '--disable-pip-version-check', '--no-input',
        '--progress-bar', 'off', '--timeout', '30', '--retries', '2',
    ]
    if dry_run:
        command.append('--dry-run')
    return [*command, '--requirement', str(requirements_file)]


def _clean_temporary_requirements(temporary: tempfile.TemporaryDirectory,
                                  *, context: str) -> None:
    """Remove one owned staging directory without replacing the active error."""
    try:
        temporary.cleanup()
    except OSError as error:
        print(
            f'Warning: could not remove temporary dependency preflight files for {context}: {error}',
            file=sys.stderr,
        )


def _preflight_and_install_requirements(python: Path, root: RootRequirements, *, context: str,
                                        target_machine: str) -> None:
    """Prove a full pinned request resolves before changing the selected venv."""
    environment = _pip_environment()
    installed = _installed_distributions(python)
    requested = _complete_requested_requirements(root, installed, target_machine=target_machine)
    staging_root = ROOT / '.tmp'
    try:
        staging_root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='bootstrap-pip-', dir=staging_root)
    except OSError as error:
        raise BootstrapError(f'Could not create temporary dependency preflight files under {staging_root}: {error}') from error

    requirements_file = Path(temporary.name) / 'requirements.txt'
    installation_started = False
    try:
        requirements_file.write_text('\n'.join(requested) + '\n', encoding='utf-8')
        print(f'Preflighting the complete requested dependency set for {context}...', flush=True)
        _run_command(
            _pip_install_command(python, requirements_file, dry_run=True),
            f'Preflighting root requirements for {context}',
            timeout=PIP_INSTALL_TIMEOUT,
            environment=environment,
            capture_output=False,
        )
        print(f'Installing preflighted root requirements into {context}...', flush=True)
        installation_started = True
        _run_command(
            _pip_install_command(python, requirements_file, dry_run=False),
            f'Installing root requirements into {context}',
            timeout=PIP_INSTALL_TIMEOUT,
            environment=environment,
            capture_output=False,
        )
    except KeyboardInterrupt:
        with ignore_interrupts():
            _clean_temporary_requirements(temporary, context=context)
            print(
                f'\nDependency initialization was cancelled. {context} may be partially changed; '
                'rerun initialization or repair that virtual environment before continuing.',
                file=sys.stderr,
            )
        raise
    except BootstrapError as error:
        with defer_interrupts():
            _clean_temporary_requirements(temporary, context=context)
        if installation_started:
            raise BootstrapError(
                f'Root requirements installation for {context} did not complete; '
                f'the virtual environment may be partially changed. {error}'
            ) from error
        raise BootstrapError(
            f'Root requirements for {context} were not changed because dependency preflight failed. {error}'
        ) from error
    except OSError as error:
        with defer_interrupts():
            _clean_temporary_requirements(temporary, context=context)
        raise BootstrapError(
            f'Could not prepare full temporary requirements for {context}; it was not changed: {error}'
        ) from error
    else:
        with defer_interrupts():
            _clean_temporary_requirements(temporary, context=context)


def _ownership_marker(venv: Path) -> tuple[Path, str]:
    token = secrets.token_hex(24)
    return venv / f'.dumper-bootstrap-creating-{token}', token


def _owns_creation(venv: Path, marker: Path, token: str) -> bool:
    try:
        return (
            venv.is_dir()
            and not venv.is_symlink()
            and marker.is_file()
            and marker.read_text(encoding='ascii') == token
        )
    except OSError:
        return False


def _cleanup_owned_creation(venv: Path, marker: Path, token: str) -> bool:
    """Remove only the directory atomically claimed by this invocation."""
    if not _owns_creation(venv, marker, token):
        return False
    try:
        shutil.rmtree(venv)
    except OSError as error:
        print(
            f'Warning: incomplete repository virtual environment remains at {venv}: {error}. '
            'Repair or remove it manually before retrying.',
            file=sys.stderr,
        )
        return False
    return True


def _create_repository_venv(venv: Path) -> None:
    """Create one absent repository .venv and clean only our interrupted work."""
    try:
        venv.mkdir()
    except FileExistsError:
        raise BootstrapError(
            f'Repository virtual environment {venv} appeared during initialization. '
            'It was not changed; rerun after the other setup process finishes.'
        ) from None
    except OSError as error:
        raise BootstrapError(f'Cannot create repository virtual-environment directory {venv}: {error}') from error

    marker, token = _ownership_marker(venv)
    try:
        marker.write_text(token, encoding='ascii')
    except OSError as error:
        raise BootstrapError(
            f'Created repository virtual-environment directory {venv}, but could not claim it for safe cleanup: {error}. '
            'It was left in place; repair or remove it manually before retrying.'
        ) from error

    print(f'Creating repository virtual environment at {venv}...', flush=True)
    try:
        _run_command(
            [sys.executable, '-I', '-m', 'venv', str(venv)],
            f'Creating repository virtual environment at {venv}',
            timeout=VENV_TIMEOUT,
            capture_output=False,
        )
    except KeyboardInterrupt:
        with ignore_interrupts():
            removed = _cleanup_owned_creation(venv, marker, token)
            if removed:
                print(
                    f'\nVirtual-environment creation was cancelled; removed the incomplete {venv}.',
                    file=sys.stderr,
                )
            else:
                print(
                    f'\nVirtual-environment creation was cancelled; {venv} was left for manual repair.',
                    file=sys.stderr,
                )
        raise
    except BootstrapError as error:
        # A new Ctrl+C during error cleanup should be delivered after the
        # bounded cleanup finishes instead of leaving a half-created venv.
        with defer_interrupts():
            removed = _cleanup_owned_creation(venv, marker, token)
        state = 'was removed' if removed else 'was left for manual repair'
        raise BootstrapError(
            f'Repository virtual-environment creation did not complete; {venv} {state}. {error}'
        ) from error
    finally:
        # A completed venv does not need the private ownership marker. A failed
        # unlink is harmless; it is never treated as authority in a later run.
        if _owns_creation(venv, marker, token):
            try:
                marker.unlink()
            except OSError:
                pass


def _repository_python() -> tuple[Path, bool]:
    """Return the verified repository interpreter and whether this run made it."""
    venv = _repository_venv()
    created = False
    if venv.exists() or venv.is_symlink():
        if venv.is_symlink() or not venv.is_dir():
            raise BootstrapError(
                f'Repository virtual environment path {venv} is not a normal directory. '
                'It was not changed; repair or recreate it manually.'
            )
        print(f'Reusing repository virtual environment at {venv}.', flush=True)
    else:
        _create_repository_venv(venv)
        created = True

    python = _venv_python(venv)
    if not python.is_file():
        raise BootstrapError(
            f'Repository virtual environment {venv} is missing {python.relative_to(venv)}. '
            'It was not changed; repair or recreate it manually.'
        )
    _fresh_venv_report(python, expected_prefix=venv)
    return python, created


def initialize_environment() -> Path:
    """Initialize/check the selected venv and return its interpreter path.

    Active real environments are selected exactly as supplied, including a
    differently named venv.  Without one, this initializes the fixed
    repository ``.venv``.  It never falls back to global pip.
    """
    root_requirements = _read_requirements()
    requirements = root_requirements.requirements
    if running_in_virtual_environment():
        python = Path(sys.executable)
        context = f'active virtual environment {sys.prefix}'
        print(f'Using {context}.', flush=True)
        _fresh_venv_report(python, expected_prefix=None)
    else:
        # A missing repository environment necessarily needs the fixed
        # requirements installation below. Reject unsafe pip routing before
        # creating even its empty directory, leaving no partial state behind.
        if not _repository_venv().exists() and not _repository_venv().is_symlink():
            _pip_environment()
        python, _created = _repository_python()
        context = f'repository virtual environment {_repository_venv()}'

    installed, target_machine = _installed_requirements(python, requirements)
    if any(
        requirement.normalized_name == 'adbutils' and installed.get(requirement.name) is False
        for requirement in requirements
    ) and shutil.which('adb') is None:
        print(
            f'Bundled ADB is skipped for host {target_machine}; all other Python setup continues. '
            'Install or build ADB manually and put it on PATH. See docs/android-setup.md#arm-hosts.',
            flush=True,
        )
    missing = _missing_or_wrong_requirements(requirements, installed)
    needs_repair = bool(missing)
    if not missing:
        environment = _pip_environment()
        try:
            _pip_check(python, context=context, environment=environment)
        except BootstrapError:
            # A cancelled install can leave root metadata intact while one of
            # its dependencies is absent. Resolve the same pinned full set once
            # so rerunning init.py can repair this case without blind upgrades.
            needs_repair = True
            print('Installed packages failed pip check; preflighting dependency repair...', flush=True)
    if needs_repair:
        # Do not let an interrupted frida install's ordinary pip-check failure
        # block its own repair. The full dry-run below keeps every non-root
        # installed package exact and refuses resolver conflicts before mutation.
        _preflight_and_install_requirements(
            python, root_requirements, context=context, target_machine=target_machine,
        )
        installed, _target_machine = _installed_requirements(python, requirements)
        missing = _missing_or_wrong_requirements(requirements, installed)
        if missing:
            raise BootstrapError(
                f'Installing root requirements into {context} completed, but these requirements are still missing or wrong: '
                f'{", ".join(missing)}.'
            )
        # Only one repair is attempted. A failed final check stops here.
        _pip_check(python, context=context, environment=_pip_environment())
    else:
        print(f'Root requirements already satisfy {context}; no package installation is needed.', flush=True)

    print(f'Virtual environment ready: {python}.', flush=True)
    return python


def _help_requested(arguments: Sequence[str]) -> bool:
    return '-h' in arguments or '--help' in arguments


def _relaunch(python: Path, entrypoint: Path, arguments: Sequence[str]) -> None:
    command = [str(python), str(entrypoint), *arguments]
    print(f'Relaunching with {python}: {entrypoint.name}', flush=True)
    if not _is_windows():
        try:
            os.execv(str(python), command)
        except OSError as error:
            raise BootstrapError(f'Could not relaunch {entrypoint} with {python}: {error}') from error
        raise BootstrapError(f'Relaunching {entrypoint} unexpectedly returned.')

    # Windows cannot replace the current process with os.execv. Keep inherited
    # terminal streams and return the child status as this launcher status.
    try:
        child = subprocess.Popen(command)
    except OSError as error:
        raise BootstrapError(f'Could not relaunch {entrypoint} with {python}: {error}') from error
    try:
        status = child.wait()
    except KeyboardInterrupt:
        with ignore_interrupts():
            _reap_windows_child_after_interrupt(child)
        raise
    except OSError as error:
        with ignore_interrupts():
            _reap_windows_child_after_interrupt(child)
        raise BootstrapError(f'Could not wait for relaunched {entrypoint}: {error}') from error
    raise SystemExit(status)


def _reap_windows_child_after_interrupt(child: subprocess.Popen) -> None:
    """Give the relaunched CLI time to finish its own Ctrl+C cleanup first."""
    try:
        child.wait(timeout=WINDOWS_RELAUNCH_INTERRUPT_GRACE)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        child.terminate()
    except OSError:
        # The child may have exited between wait() and terminate().
        pass
    try:
        child.wait(timeout=WINDOWS_RELAUNCH_REAP_TIMEOUT)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        child.kill()
    except OSError:
        pass
    try:
        child.wait(timeout=WINDOWS_RELAUNCH_REAP_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        print(
            'Warning: could not reap the relaunched Windows Python process after cancellation; '
            'check Task Manager before retrying.',
            file=sys.stderr,
        )


def bootstrap(entrypoint: Path, argv: Sequence[str] | None = None) -> None:
    """Relaunch a normal CLI through ``.venv`` when no venv is active.

    Help stays available without creating a virtual environment or invoking
    pip.  A real active venv is a strict no-op so normal commands preserve its
    package state; use ``init.py`` for an explicit check or repair there.
    """
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if _help_requested(arguments) or running_in_virtual_environment():
        return
    script = Path(entrypoint).resolve()
    if not script.is_file():
        raise BootstrapError(f'Bootstrap entry point is not a file: {script}')
    python = initialize_environment()
    _relaunch(python, script, arguments)
