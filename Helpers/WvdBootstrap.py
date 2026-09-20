"""Dedicated, stdlib-only startup guard for the optional WVD generator."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Sequence

from Helpers import Bootstrap


WVD_VENV_NAME = '.venv-wvd'
WVD_REQUIREMENTS_NAME = 'requirements-wvd.txt'
BootstrapError = Bootstrap.BootstrapError


def initialize_project_environments() -> tuple[Path, Path]:
    """Prepare main and WVD requirements through separate verified interpreters.

    A custom active main venv remains supported. When init.py itself is run
    inside .venv-wvd, select the repository .venv for main requirements instead
    of attempting to install the incompatible requirement sets together.
    """
    wvd = Bootstrap.ROOT / WVD_VENV_NAME
    active_is_wvd = (
        Bootstrap.running_in_virtual_environment()
        and Path(sys.prefix).resolve() == wvd.resolve()
    )
    main_python = Bootstrap.initialize_environment(
        use_active_environment=not active_is_wvd, rebuild_corrupt=True,
    )
    wvd_python = Bootstrap.initialize_dedicated_environment(
        venv_name=WVD_VENV_NAME,
        requirements_file=Bootstrap.ROOT / WVD_REQUIREMENTS_NAME,
        use_active_environment=False,
        rebuild_corrupt=True,
    )
    return main_python, wvd_python


def bootstrap_wvd(entrypoint: Path, argv: Sequence[str] | None = None) -> None:
    """Run the WVD tool only through its isolated repository environment."""
    Bootstrap.bootstrap_dedicated(
        entrypoint,
        venv_name=WVD_VENV_NAME,
        requirements_file=Bootstrap.ROOT / WVD_REQUIREMENTS_NAME,
        argv=argv,
    )
