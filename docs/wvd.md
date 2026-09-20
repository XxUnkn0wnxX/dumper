# 📦 WVD generation

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🧩 Dumper operation](dumper.md)

`tools/generate_wvd.py` converts captured
`client_id.bin` and `private_key.pem` pairs into Android L3 WVD v2 files using
the public [`pywidevine`](https://github.com/devine-dl/pywidevine) API. The
helper discovers pair folders recursively below the repository's fixed
`key_dumps/` root, regardless of the current working directory. It requires no
Android connection and does not use ADB, Frida, Chrome, license requests, or a
live license check. Its checks establish local file integrity, not
license-service acceptance.

## Environment boundary

WVD generation requires the repository's dedicated **`.venv-wvd`** environment.
`pywidevine==1.9.0` requires `protobuf>=6.33.0,<7.0.0`, while the main dumper
environment uses `protobuf==7.36.2`. Do not install both requirements files in
one environment or bypass dependency checks with `--no-deps`.

The helper uses shared bootstrap behavior with a strict boundary:

- Outside any real virtual environment, it creates or checks `.venv-wvd`,
  installs or repairs its requirements only when needed, and relaunches under
  that interpreter before scanning or converting pairs.
- Inside the main `.venv` or another custom environment, it refuses before
  touching packages or input data. Deactivate that environment first.
- An explicit `.venv-wvd/bin/python` (or Windows `Scripts\python.exe`) works
  even if the shell's `VIRTUAL_ENV` still names the main environment.
- `--help` works without an environment, dependencies, or setup.

`init.py` prepares both environments in one command: the main requirements go
to `.venv` or an accepted active custom main venv, and the WVD requirements go
only to `.venv-wvd`. Healthy existing environments are checked without package
mutation; a fixed repository environment with a broken interpreter/configuration
or broken installed dependency graph is deleted and recreated from scratch.
Ordinary missing requirements or changed pins use the dependency resolver. The
normal dumper/bootstrap fallback prepares only the main `.venv`, while the WVD
generator fallback prepares only `.venv-wvd`. Running the WVD generator while a
main or custom venv is active still refuses before package or input-data work.

The dedicated requirements file is [`requirements-wvd.txt`](../requirements-wvd.txt).
The main dumper environment remains separate:

| Work | Environment | Requirements |
| --- | --- | --- |
| Dumper, Frida, and protobuf maintenance | `.venv` or an active custom environment | [`requirements.txt`](../requirements.txt) |
| WVD generation | `.venv-wvd` only | [`requirements-wvd.txt`](../requirements-wvd.txt) |

## Automatic setup and run

Run from the repository root. If the main environment is active, deactivate it
before the first automatic WVD command:

```sh
deactivate  # only when a main/custom environment is active
python3 tools/generate_wvd.py --help
python3 tools/generate_wvd.py
```

The first command only prints help. The second command performs the dedicated
environment check/bootstrap, then scans `key_dumps/` and reports each converted
or skipped pair. It accepts no data-path or conversion options.

In Windows PowerShell:

```powershell
deactivate  # only when a main/custom environment is active
py -3 tools\generate_wvd.py --help
py -3 tools\generate_wvd.py
```

## Manual `.venv-wvd` setup

Use the `.venv-wvd` interpreter for every WVD command. On macOS or Linux:

```sh
deactivate  # only when a main/custom environment is active
python3 -m venv .venv-wvd
.venv-wvd/bin/python -m pip install --upgrade -r requirements-wvd.txt
.venv-wvd/bin/python -m pip check
.venv-wvd/bin/python tools/generate_wvd.py
```

On Windows PowerShell:

```powershell
deactivate  # only when a main/custom environment is active
py -3 -m venv .venv-wvd
.venv-wvd\Scripts\python.exe -m pip install --upgrade -r requirements-wvd.txt
.venv-wvd\Scripts\python.exe -m pip check
.venv-wvd\Scripts\python.exe tools\generate_wvd.py
```

Activation is optional. You can activate `.venv-wvd` and use its plain `python`,
or invoke `.venv-wvd/bin/python` or `.venv-wvd\Scripts\python.exe` directly;
the explicit interpreter paths avoid shell-activation confusion.

## Command-line interface

The helper has no conversion flags or positional arguments:

| Argument | Purpose | Example |
| --- | --- | --- |
| `-h`, `--help` | Show help and exit without environment, dependency, or data setup. | `python3 tools/generate_wvd.py --help` |
| *(no arguments)* | Recursively scan the fixed repository `key_dumps/` root and process every eligible pair. | `python3 tools/generate_wvd.py` |

## Pair discovery and validation

**Source files are read-only to this tool.** It never edits, renames, deletes,
or changes permissions on `client_id.bin` or `private_key.pem`. Conversion
writes only inside the pair's `WVD/` folder.

An eligible input folder contains both files in the same directory:

```text
key_dumps/
└── <device>/
    └── private_keys/
        └── CDM <version> - API <level>/
            ├── client_id.bin
            └── private_key.pem
```

The helper parses the Android L3 client ID, loads the private key, and locally
matches the RSA certificate before serialization. Invalid, incomplete,
mismatched, or private-key-less folders are reported and skipped; other valid
pairs continue processing. Pair discovery and output do not traverse symlinks.
The local match is a file validation step, not a license request or server
check.

Each result prints `Created`, `Replaced`, or `Skipped` and the file or folder
path relative to the repository root, beginning with `key_dumps/`. Skipped
folders include the reason, such as a missing `client_id.bin` or
`private_key.pem`, malformed data, or a private key that does not match the
client certificate. Output-write failures are reported separately.

## Output and replacement

For a pair without an existing direct WVD file, the helper creates:

```text
key_dumps/
└── <device>/
    └── private_keys/
        └── CDM <version> - API <level>/
            ├── client_id.bin
            ├── private_key.pem
            └── WVD/
                └── google_sdk_gphone_x86_64_17.0.0_c3806ca2_22596_l3.wvd
```

When no direct WVD file exists, the generated filename follows the upstream
manufacturer/model/optional-CDM-version/WVD-checksum/system-ID/L3 convention. For
example, `google_sdk_gphone_x86_64_17.0.0_c3806ca2_22596_l3.wvd` contains the
manufacturer and model, the available CDM version, the WVD checksum, system
ID, and the `l3` marker. The optional CDM component is omitted when unavailable.
If `WVD/` already contains direct `.wvd` files, the helper overwrites every
such file while preserving its existing filename. Other files and directories
are untouched. Writes are atomic: an interruption leaves the old destination
until its replacement is complete, and only helper-owned temporary files are
cleaned up.

The WVD uses Android L3 device metadata and the public pywidevine device APIs.
Serialization parsing and RSA certificate matching are local integrity checks.

## Exit statuses and references

| Status | Meaning |
| ---: | --- |
| `0` | All eligible pairs completed successfully. |
| `1` | A pair was skipped or failed, scanning failed, no pairs were found, or environment setup failed. |
| `130` | The user cancelled with Ctrl+C. |

The upstream project and public API references are
[devine-dl/pywidevine](https://github.com/devine-dl/pywidevine), especially its
`device.py` and `main.py` implementations.
