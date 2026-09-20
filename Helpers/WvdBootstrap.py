"""Dedicated, stdlib-only startup guard for the optional WVD generator."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from Helpers import Bootstrap


WVD_VENV_NAME = '.venv-wvd'
WVD_REQUIREMENTS_NAME = 'requirements-wvd.txt'
BootstrapError = Bootstrap.BootstrapError


def bootstrap_wvd(entrypoint: Path, argv: Sequence[str] | None = None) -> None:
    """Run the WVD tool only through its isolated repository environment."""
    Bootstrap.bootstrap_dedicated(
        entrypoint,
        venv_name=WVD_VENV_NAME,
        requirements_file=Bootstrap.ROOT / WVD_REQUIREMENTS_NAME,
        argv=argv,
    )
