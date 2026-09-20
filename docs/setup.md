# 🧱 Checkout and Python setup

[← Back to the Dumper README](../README.md) · [📱 Android setup](android-setup.md) · [🧰 Frida setup](frida-setup.md) · [🧪 Testing](testing.md)

This guide owns repository initialization, the dumper virtual environment, and
the regular Python requirements. Run the commands from the repository root.
The [Android setup guide](android-setup.md) owns Platform-Tools, emulator/root
images, and device authorization; the [Frida setup guide](frida-setup.md) owns
the server helper.

Normal use has no compilation step. The repository includes the generated
protobuf module; `protoc` is only needed for optional [maintainer regeneration](protobuf.md).

## Initialize a checkout

The maintained fork uses the `develop` branch. To create a fresh checkout, run
the following from a directory where you keep source code:

```sh
git clone --branch develop https://github.com/XxUnkn0wnxX/dumper.git
cd dumper
```

If you already have this repository, change to its root instead. All paths in
the guides assume that root, where `dump_keys.py`, `requirements.txt`, and
`tools/` are present.

## Requirements

| Component | Requirement |
| --- | --- |
| Python | [Python 3.10 or newer](https://www.python.org/downloads/) on the computer. Tested up to Python 3.14; current development and regression checks use Python 3.14.0. |
| Android | A rooted device or root-capable emulator with USB debugging enabled. See [Android setup](android-setup.md). |
| ADB | Android SDK Platform-Tools installed globally and available on `PATH` when possible. The root requirements also install the pinned `adbutils` wheel on supported hosts as a bundled fallback; see [ADB resolution](android-setup.md#adb-resolution). |
| Frida | A running Android `frida-server` with root access and a version matching the host's Python `frida` package. See [Frida setup](frida-setup.md). |
| Request layout | A recognized exported signature, or a verified manual layout override for the target library. See [dumper operation](dumper.md#layout-detection-and-options). |

The root requirements include `adbutils==2.12.0` with a binary-only wheel
constraint, so `init.py` installs the packaged ADB fallback as part of normal
environment initialization on supported Intel/AMD hosts. Native ARM hosts skip
that dependency because upstream provides no matching wheel; use system ADB
there. Install Android SDK Platform-Tools globally and
put `adb` on `PATH` when possible; the setup helper always prefers that PATH
executable. The packaged wheel is used only when PATH does not provide ADB.

## Automatic environment setup

**Recommended first step for a new checkout: run `init.py` before the dumper or
tools.** This prepares Python dependencies and checks them without contacting
Android or starting a server:

```sh
python3 init.py
```

On Windows, run `py -3 init.py`. You can rerun this command whenever you want
to check or repair the selected environment's main requirements.

The dumper, `full_auto.py`, `setup_frida.py`, and `regenerate_protobuf.py` share
[`Helpers/Bootstrap.py`](../Helpers/Bootstrap.py) with `init.py`. As a fallback
for a skipped initialization step, when started **outside a
virtual environment**, they create or reuse the repository's `.venv`, install
the main requirements when needed, and restart the same script with its
arguments inside that environment:

```sh
python3 tools/setup_frida.py
# In a second terminal, from the repository root:
python3 dump_keys.py
```

On Windows, use `py -3 tools\setup_frida.py` and `py -3 dump_keys.py`.
The protobuf tool uses the same initialization path. `--help` shows help without
creating an environment or installing packages. Python itself must already be
installed; on Linux, the Python `venv` support package may also be needed.

Automatic setup uses the running Python interpreter to create the environment
and detects the OS when selecting its executable: `bin/python` on macOS/Linux
or `Scripts\python.exe` on Windows. Shell activation is unnecessary. The
[WVD helper](wvd.md) uses the same platform handling with its separate
`.venv-wvd` environment.

[`init.py`](../init.py) uses the same shared
helper, installs missing or mismatched main requirements in the selected venv,
and runs `pip check`. It uses an active custom venv when present; otherwise it
creates or reuses `.venv`. It exits after reporting the result. A successful
check confirms Python dependencies, including the bundled ADB fallback, not
Android or Frida-server readiness.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| *(no option)* | Initialize the selected venv, ensure the main requirements, and check dependencies. | Setup and check | `python3 init.py` |
| `-h`, `--help` | Show help without environment creation or package installation. | — | `python3 init.py --help` |

**Any already active Python virtual environment is accepted**, including one
with a custom name or location. Normal dumper/tool startup keeps using that
interpreter without automatically changing its dependencies during
initialization. Run `init.py` there or install the requirements manually as
shown below. The Frida helper's separate
[version synchronization](frida-setup.md#host-python-package-synchronization)
can still update its Frida packages before deployment.

Automatic setup uses the running Python 3 interpreter's `-m venv` command and
the environment's own pip; it never installs into global site packages. An
existing environment that satisfies the requirements is reused without a
package installation. Installation does not request blanket upgrades, so it
preserves an already compatible Frida version. Setup failures stop the command
before its normal work begins. Ctrl+C cancels initialization cleanly; an
existing environment is never deleted as cleanup.

When packages need changing, initialization resolves the full installed
dependency set first and holds unrelated packages at their current versions.
An incompatible set stops before installation. A partial pip installation is
not rolled back; rerun `init.py` to repair missing main requirements, or follow
the reported dependency-conflict guidance. Automatic installation ignores pip
configuration files to keep its destination inside the selected venv; index,
proxy and certificate environment variables are preserved, while overrides
that redirect installation or bypass dependency resolution are rejected.

Restarting under the venv is local to the command: it does not activate the
environment in your parent terminal. Continue using `python3 script.py`, invoke
the venv's Python directly, or activate it manually. Initialization covers
Python dependencies only; ADB, Android root access, and the optional `protoc`
compiler still follow their dedicated guides. WVD tooling remains separate.

## Manual environment setup

On macOS or Linux, run:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade -r requirements.txt
```

In Windows PowerShell, run:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade -r requirements.txt
```

If PowerShell's execution policy prevents activation, use
`.venv\Scripts\python.exe` in the commands below instead. Activation is
optional when the environment's interpreter is invoked directly.

`frida`, `frida-tools`, and `pycryptodome` are unpinned, so `--upgrade` asks pip
for the latest compatible releases. `frida-tools` supplies the Frida command
line tools. Keep the host and server versions matched when updating.
The Frida setup helper automatically synchronizes the `frida` package in its
virtual environment with the server it will deploy, including explicit older
versions. See [package synchronization](frida-setup.md#host-python-package-synchronization)
for dependency checks and failure behavior.

Protobuf is pinned to the runtime supported by the shipped
[generated binding](../Helpers/wv_proto2_pb2.py). Normal installation uses that
file directly. Maintainers can rebuild it using the checked-in schema with the
[protobuf guide](protobuf.md); normal users do not need `protoc`.

## Run the dumper or tools

After activation, run the dumper from the repository root:

```sh
python dump_keys.py
```

Run the Frida and protobuf tools from the same active environment:

```sh
python tools/setup_frida.py
python tools/regenerate_protobuf.py --check
```

On Windows PowerShell, use the same commands with Windows path separators when
referring to a script:

```powershell
python tools\setup_frida.py
python tools\regenerate_protobuf.py --check
```

The [dumper guide](dumper.md), [Frida guide](frida-setup.md), and
[protobuf guide](protobuf.md) contain their full argument tables. The main
README keeps only the shortest capture walkthrough.

## Optional WVD tooling

Optional `pywidevine` tooling has its own
[requirements-wvd.txt](../requirements-wvd.txt) and needs a **separate
`.venv-wvd` environment** because its Protobuf requirements conflict with the
dumper's. Do not install both requirements files into one environment or bypass
dependency checks with `--no-deps`. The WVD helper is a focused exception to
the main CLI environment behavior: outside a real venv it bootstraps strict
`.venv-wvd`, while an active main or custom venv is refused before package or
data operations. See the [WVD environment boundary](wvd.md#environment-boundary)
and its pinned environment commands.
