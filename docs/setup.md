# 🧱 Checkout and Python setup

[← Back to the Dumper README](../README.md) · [📱 Android setup](android-setup.md) · [🧰 Frida setup](frida-setup.md) · [🧪 Testing](testing.md)

This guide owns repository initialization, the dumper virtual environment, the
dedicated WVD environment, and their separate Python requirements. Install the
computer prerequisites first; after cloning, run project commands from the
repository root.
The [Android setup guide](android-setup.md) owns Platform-Tools, emulator/root
images, and device authorization; the [Frida setup guide](frida-setup.md) owns
the server helper.

Normal use has no compilation step. The repository includes the generated
protobuf module; `protoc` is only needed for optional [maintainer regeneration](protobuf.md).

## Install Python and Git

For a new installation, prefer **Python 3.14**. The project requires Python
3.10 or newer and is tested up to 3.14; your Linux distribution may provide an
older compatible version. Install Git too, so the checkout command below works.
If both are already installed, check their versions and skip the matching steps.

| Computer | Installation route | Check Python |
| --- | --- | --- |
| macOS | Command Line Tools → Homebrew → `python@3.14` | `python3.14 --version` |
| Windows | Administrator PowerShell → Chocolatey → `python314` | `py -3.14 --version` |
| Linux | Your distribution's package manager | `python3 --version`, or `python3.14 --version` for the explicit 3.14 route |

<details>
<summary>🍎 macOS — Command Line Tools, Homebrew, and Python 3.14</summary>

Open **Terminal**. Apple's **Command Line Tools are sufficient** for this
setup; the full Xcode application is not required. Install the tools and wait
for the graphical installer to finish:

```sh
xcode-select --install
```

If macOS says the tools are already installed, continue. See
[Apple's Command Line Tools guide](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools/)
and [Homebrew's requirements](https://docs.brew.sh/Installation#macos-requirements).

If Homebrew is missing, run its [official installer](https://brew.sh/):

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Follow the installer's printed “Next steps” before continuing.** Those
commands add Homebrew to your shell configuration and current `PATH`.
The usual prefix is `/opt/homebrew` on Apple Silicon and `/usr/local` on Intel;
use the commands printed for your installation. Confirm that `brew --version`
works in a new Terminal window.

Install the [Python 3.14 formula](https://formulae.brew.sh/formula/python@3.14)
and Git, then verify them:

```sh
brew install python@3.14 git
python3.14 --version
python3.14 -m pip --version
git --version
```

Use `python3.14 init.py` after cloning if another Python takes precedence over
`python3` on your `PATH`. Homebrew's current support requirements may exclude
older macOS releases, including Big Sur. Check those requirements before a
fresh install; the [official Python macOS installers](https://www.python.org/downloads/macos/)
are another option when their listed OS requirements match your computer.

</details>

<details>
<summary>🪟 Windows — Chocolatey, optional GUI, and Python 3.14</summary>

Open Start, search for **Windows PowerShell**, right-click it, and select
**Run as administrator**. Accept the Windows elevation prompt. If Chocolatey
is not installed, run these commands from its
[official PowerShell installation instructions](https://docs.chocolatey.org/en-us/choco/setup/#install-with-powershellexe):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

`-Scope Process` applies the execution-policy bypass only to this PowerShell
session; it does not permanently change the machine's policy. Managed
organization policies can still take precedence. The last command downloads
and runs Chocolatey's official installer.

Close that window and open a **new administrator PowerShell** so it sees
Chocolatey's updated `PATH`. Install its
[`python314`](https://community.chocolatey.org/packages/python314) and
[`git`](https://community.chocolatey.org/packages/git) packages:

```powershell
choco --version
choco install python314 git -y
```

The `python314` package selects the available 3.14 patch release. To add the
optional graphical package manager, run
[Chocolatey GUI's install command](https://docs.chocolatey.org/en-us/chocolatey-gui/setup/installation/)
in that administrator window:

```powershell
choco install chocolateygui -y
```

Close the administrator window. Open a **normal PowerShell** for cloning and
running this project, then verify:

```powershell
py -3.14 --version
py -3.14 -m pip --version
git --version
```

Use `py -3.14 init.py` after cloning to select 3.14 explicitly. The shorter
`py -3` examples elsewhere select an installed Python 3 and may choose a
different version if several are installed. See
[Python's Windows guide](https://docs.python.org/3.14/using/windows.html).
Project initialization and normal use do not need administrator PowerShell or
a permanent execution-policy change.

</details>

<details>
<summary>🐧 Linux — Ubuntu/Debian, Fedora, and Arch</summary>

Use the package manager for your distribution. These commands install the
distribution's Python, pip, Git, and virtual-environment support; the default
Python version depends on the distribution and release.

**Ubuntu / Debian / Linux Mint:**

```sh
sudo apt update
sudo apt install python3 python3-venv python3-pip git
```

These are the official [Ubuntu Python](https://packages.ubuntu.com/search?keywords=python3&searchon=names&exact=1)
and [venv](https://packages.ubuntu.com/search?keywords=python3-venv&searchon=names&exact=1) packages, with
[Debian equivalents](https://packages.debian.org/stable/python3-venv).
The version depends on your release: older releases may supply 3.12 or 3.13,
while newer ones may already provide 3.14. You do not need to add an unofficial
repository or mix testing packages into a stable system for 3.14.

**Fedora:**

Prefer the official
[`python3.14` package](https://packages.fedoraproject.org/pkgs/python3.14/python3.14/),
when available for your Fedora release, to select 3.14 explicitly:

```sh
sudo dnf install python3.14 git
python3.14 --version
python3.14 -m venv --help
```

Use `python3.14 init.py` after cloning. Its
[library package](https://packages.fedoraproject.org/pkgs/python3.14/python3.14-libs/fedora-45.html)
includes `venv` and `ensurepip`, so it creates pip inside the project environment;
a system pip package for a different default Python is unnecessary for that route.

If your release does not offer `python3.14`, use
`sudo dnf install python3 python3-pip git` and check `python3 --version`.
Use a Python 3.10–3.14 interpreter for the tested range; a rolling/development
distribution's default may already be newer.

**Arch Linux:**

```sh
sudo pacman -Syu python python-pip git
```

The Arch command also performs the normal full system update; review its
transaction before confirming. On Fedora and Arch, `venv` comes with Python
rather than a separate `python3-venv` package. See Arch's
[`python` package](https://archlinux.org/packages/core/x86_64/python/) and
[Git's Linux installation guide](https://git-scm.com/install/linux).

For the default-interpreter commands, verify the interpreter and tools:

```sh
python3 --version
python3 -m pip --version
python3 -m venv --help
git --version
```

If your distribution provides Python 3.10–3.13, that meets the project's
minimum. Do not replace the system Python or change `/usr/bin/python3` just
to select 3.14. A separately installed `python3.14` can run `init.py` or
`-m venv` directly while the system interpreter stays in place. Python versions
newer than 3.14 have not been validated by this project. Install project
requirements inside a venv, as described below and in the
[Python packaging guide](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/).

</details>

Python installation does not install Android Studio or the Android SDK.
Continue with [Android Studio installation](android-setup.md#install-android-studio)
and [Platform-Tools / ADB](android-setup.md#install-adb-on-the-computer) for the
Windows, macOS, and Linux instructions. A physical-device setup can use
Platform-Tools without installing the full Android Studio IDE.

## Initialize a checkout

Use the `main` branch for normal setup; ongoing changes are developed on
`develop`. To create a fresh checkout, run the following from a directory where
you keep source code. The SSH command requires an SSH key configured with your
GitHub account:

```sh
git clone --branch main git@github.com:XxUnkn0wnxX/dumper.git
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
tools.** This creates missing or checks/repairs existing Python environments
and their separate requirements without contacting Android or starting a server:

```sh
python3 init.py
```

On Windows, run `py -3 init.py`. You can rerun this command to check both
environments and repair incomplete ones. Healthy environments are reused
without package mutation.

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
`.venv-wvd` environment. The normal dumper/bootstrap fallback prepares only
the main `.venv`; WVD generator fallback prepares only `.venv-wvd`.

[`init.py`](../init.py) uses the shared helpers to create missing or check
existing main and WVD environments, with separate requirements and `pip check`
runs. It uses an active custom main venv when present; otherwise it creates or
checks `.venv`. If `.venv-wvd` is active, it selects `.venv` for the main
requirements and still checks the dedicated WVD environment. Healthy existing
environments are checked without package mutation. Missing interpreter/config
files or a failed check of the installed dependency graph cause a fixed
repository environment to be deleted and recreated from scratch. Ordinary
missing requirements or changed package pins use the dependency resolver instead.
The helper uses Python's `shutil.rmtree()` on all three operating systems.
A successful check confirms Python dependencies,
including the bundled ADB fallback, not Android or Frida-server readiness.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| *(no option)* | Create missing or check/repair existing main and WVD environments and their separate requirements. | Setup and check | `python3 init.py` |
| `-h`, `--help` | Show help without environment creation or package installation. | — | `python3 init.py --help` |

**Any already active custom main Python virtual environment is accepted.**
Normal dumper/tool startup keeps using that interpreter. Run `init.py` there to
check its main requirements and the dedicated WVD environment, or install the
requirements manually as shown below. The Frida helper's separate
[version synchronization](frida-setup.md#host-python-package-synchronization)
can still update its Frida packages before deployment.

`frida` and `frida-tools` remain unpinned. A compatible Frida upgrade or downgrade
by the setup helper is accepted and does not trigger a rebuild. Custom active
environments receive the existing dependency repair checks and are never
recursively deleted. Automatic deletion is limited to the real `.venv` and
`.venv-wvd` directories in this checkout; symlinked directories are refused.
If Windows reports files in use during removal, close processes using that
environment and rerun `init.py` with system Python outside the venv.
When the damaged environment is running `init.py` itself on Windows, setup
stops before deleting it and asks for that system-Python rerun. Before any
rebuild, a disposable `.tmp/` probe verifies that base Python can create an
environment with working pip; missing OS venv support leaves the old one intact.

Automatic setup uses the running Python 3 interpreter's `-m venv` command and
the environment's own pip; it never installs into global site packages. An
existing healthy environment is checked without package installation. A
missing environment is created, and a broken fixed repository environment is
deleted and recreated with only its own requirements. Setup failures stop the command
before its normal work begins; network or dependency-resolution failures do not
trigger a rebuild. Ctrl+C cancels initialization cleanly.

When an environment needs packages, initialization resolves the full installed
dependency set first and holds unrelated packages at their current versions.
An incompatible set stops before installation. Automatic installation ignores
pip configuration files to keep its destination inside the selected venv; index,
proxy and certificate environment variables are preserved, while overrides that
redirect installation or bypass dependency resolution are rejected.

Bootstrap progress and error messages show repository paths relative to its
root. Pip runs from that root with a relative `.tmp/.../requirements.txt` input,
so its requirement-source messages use the same path convention.

Restarting under the venv is local to the command: it does not activate the
environment in your parent terminal. Continue using `python3 script.py`, invoke
the venv's Python directly, or activate it manually. Initialization covers
Python dependencies only; ADB, Android root access, and the optional `protoc`
compiler still follow their dedicated guides. WVD tooling remains separate.

## Manual environment setup

To select 3.14 explicitly, use `python3.14` on macOS/Linux or `py -3.14` on
Windows for the environment-creation command. Once activated, `python` refers
to that environment's interpreter.

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
