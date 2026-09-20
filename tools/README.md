# 🧰 Maintainer tools

[← Back to the Dumper README](../README.md)

This directory contains optional helpers for device setup and maintaining the
shipped Protobuf binding. Run the examples from the repository root. The helper
source stays beside this guide: [`setup_frida.py`](setup_frida.py) and
[`regenerate_protobuf.py`](regenerate_protobuf.py).

| Guide | Use it for |
| --- | --- |
| 📱 [Frida server setup](#frida-server-setup) | Prepare an Android device or open its shell. |
| 🧬 [Protobuf regeneration](#protobuf-regeneration) | Regenerate or verify the shipped Python binding. |

For schema origin and archive inventory, see [Helpers source provenance](../Helpers/README.md#source-provenance)
and the [archived WKS-KEYS protobuf sources](../archives/wks-keys/README.md).

## Frida server setup

[`setup_frida.py`](setup_frida.py) downloads an Android Frida server from the official
[Frida releases](https://github.com/frida/frida/releases), installs it as
`/data/local/tmp/frida-server`, and opens an interactive root shell in that
directory. You start the server yourself by entering `./frida-server`.

Use the helper for repeat test-device setups or to prepare several maintainer
devices one at a time. Device selection, architecture, and release version can
all be specified independently or combined in the same invocation.

The helper uses Python 3.10 or newer and the standard library. It requires an
online, rooted Android device or a root-capable emulator, plus ADB on the computer.
It does not root an unrooted device. The shell-only mode described below can also
connect as the normal ADB user.

No virtual environment or additional Python requirements are needed when ADB is
installed on the system. You can replace `.venv/bin/python` in the examples with
`python3` (or `py -3` on Windows). Using the dumper's environment lets the helper
check its installed Python `frida` version when preparing the server.

### Choose an emulator image

For Android Studio emulator testing across API 28–33, prefer **Services → Google
APIs** when selecting the system image. Root availability depends on the image's
build configuration, not just its Android/API version.

| Image choice | Root access for dumper testing |
| --- | --- |
| **Google APIs** | Preferred: select a root-capable `userdebug` or `eng` build and verify `adb root` after boot. A standalone `su` binary is not required. |
| **Google Play Store** | Stock production images typically have no `su` and disallow `adb root`; they require separate rooting work before the helper can install the server. |

Android documents the [root restriction on Play Store images](https://developer.android.com/studio/run/managing-avds#system-images).
For the debug-root route, look for `ro.debuggable=1` and a `userdebug` or `eng`
build. These properties belong to the image; they are not an AVD checkbox.
The decisive check is a working root shell, as described in
[AOSP's ADB root documentation](https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/docs/dev/root.md).

<details>
<summary>🔎 Verify root after booting the emulator</summary>

After installing ADB as described below, replace `emulator-5554` with the serial
reported by `adb devices -l`:

```sh
adb -s emulator-5554 shell getprop ro.debuggable
adb -s emulator-5554 shell getprop ro.build.type
adb -s emulator-5554 root
adb -s emulator-5554 wait-for-device
adb -s emulator-5554 shell id
```

Expect `1`, `userdebug` (or `eng`), and finally `uid=0(root)`. `adb root` restarts
the device's ADB daemon. If it reports `adbd cannot run as root in production
builds`, use a root-capable image or root the device separately.

Normal helper installation already tries `adb root` if existing root and `su`
are unavailable. `--shell` only uses existing privileges, so run `adb root` first
when you want a root shell on an image without `su`.

</details>

### Install ADB on the computer

Install Android SDK Platform-Tools globally or place its `platform-tools`
directory on your system `PATH`, so `adb version` works in a new terminal.
Android Studio's SDK Manager can also install Platform-Tools.

| System | Installation |
| --- | --- |
| Windows | Download **SDK Platform-Tools for Windows** from [Android's official downloads](https://developer.android.com/tools/releases/platform-tools#downloads), extract it, and add the directory containing `adb.exe` to `PATH`. Physical devices may also need a manufacturer's [USB driver](https://developer.android.com/studio/run/oem-usb). |
| macOS | Install the [Homebrew android-platform-tools cask](https://formulae.brew.sh/cask/android-platform-tools) with `brew install --cask android-platform-tools`, or use **SDK Platform-Tools for Mac** from [Android's downloads](https://developer.android.com/tools/releases/platform-tools#downloads). |
| Linux | Download **SDK Platform-Tools for Linux** from [Android's downloads](https://developer.android.com/tools/releases/platform-tools#downloads) and add the extracted directory to `PATH`, or install your distribution's ADB package. For USB permissions, follow Android's [Linux device setup](https://developer.android.com/studio/run/device#setting-up). |

Check the installation and device authorization:

```sh
adb version
adb devices -l
```

Wait until Android has finished booting, enable USB debugging when using a
physical device, and accept its authorization prompt. A usable entry looks like:

```text
List of devices attached
emulator-5554  device
```

Only entries whose state is exactly `device` are eligible. Entries marked
`offline`, `unauthorized`, or another state are skipped. With multiple online
devices, select one explicitly using `--device-id`.

<details>
<summary>🧩 Optional ADB through pip</summary>

The [adbutils wheels](https://pypi.org/project/adbutils/) include a native ADB
binary on supported host platforms. To use one inside the project's virtual
environment instead of a system installation:

```sh
.venv/bin/python -m pip install --only-binary=adbutils adbutils
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.
The wheel requirement prevents falling back to a source distribution without a
bundled executable. Wheel availability depends on the host OS and architecture;
use Platform-Tools if pip cannot find a compatible wheel.

The helper searches for ADB in this order: an explicit `--adb` path, `adb` on
`PATH`, then the binary bundled with `adbutils` in the Python environment running
the helper. It does not install packages automatically. The optional pip package
is not added to the dumper's regular requirements. It also does not create a
standalone `adb` shell command; this helper can locate its bundled binary directly.

</details>

### Install and open the device shell

From the repository root, in an interactive terminal:

```sh
.venv/bin/python tools/setup_frida.py
```

This selects the latest stable Frida release and detects the server architecture
from Android's primary CPU ABI before downloading:

| Android primary ABI | Frida server architecture |
| --- | --- |
| `x86_64` | `x86_64` (64-bit Intel/AMD) |
| `x86` | `x86` (32-bit Intel/AMD) |
| `arm64-v8a` | `arm64` (64-bit ARM) |
| `armeabi-v7a` | `arm` (32-bit ARM) |

For example, an x86_64 emulator receives the x86_64 build, while a physical
Pixel 6 Pro receives the ARM64 build. You can also select an architecture
explicitly:

```sh
.venv/bin/python tools/setup_frida.py --arch arm64
```

`x86` and `arm` select 32-bit builds; `x86_64` and `arm64` select 64-bit builds.
The check uses the device's primary Android ABI, so a different selection is
rejected even if the device also advertises a compatibility ABI.

To select a specific Frida release or a device:

```sh
.venv/bin/python tools/setup_frida.py --ver 16.3.3
.venv/bin/python tools/setup_frida.py --device-id emulator-5554
.venv/bin/python tools/setup_frida.py --device-id emulator-5554 --arch x86_64 --ver 16.3.3
```

Options can be combined. On Windows, for example:

```powershell
.venv\Scripts\python.exe tools\setup_frida.py --ver 16.3.3 --device-id emulator-5554 --adb "C:\Android\platform-tools\adb.exe"
```

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| `-h`, `--help` | Show the complete helper help and exit. | — | `.venv/bin/python tools/setup_frida.py --help` |
| `--ver VERSION` | Download a specific `X.Y.Z` Frida release instead of the latest stable release. | Latest stable release | `.venv/bin/python tools/setup_frida.py --ver 16.3.3` |
| `--arch {auto,x86_64,x86,arm64,arm}` | Detect the primary ABI with `auto`, or select one of the four explicit architectures; an explicit choice must match the device's primary ABI. | `auto` | `.venv/bin/python tools/setup_frida.py --arch arm64` |
| `--device-id SERIAL`, `-s SERIAL` | Select an online ADB device explicitly. | The only online `device` entry | `.venv/bin/python tools/setup_frida.py --device-id emulator-5554` |
| `--adb PATH` | Use a specific `adb` or `adb.exe` executable. | `adb` on `PATH`, then an `adbutils` bundled binary | `.venv/bin/python tools/setup_frida.py --adb /opt/android/platform-tools/adb` |
| `--no-shell` | Install and exit without opening the interactive shell; mutually exclusive with `--shell`. | Off; the default install flow opens a shell | `.venv/bin/python tools/setup_frida.py --no-shell` |
| `--shell` | Open only a shell in `/data/local/tmp`, preferring root or `su` and falling back to the normal ADB user; mutually exclusive with `--no-shell`, `--ver`, and a manual (non-`auto`) `--arch`. | Off | `.venv/bin/python tools/setup_frida.py --shell` |

The helper first checks whether the ADB shell is already root. Otherwise it tries
`su -c` and the emulator-style `su 0 sh -c`. Approve any root-manager prompt on
Android. If neither works, it tries `adb root`, which can restart the device's ADB
daemon, waits for that device to reconnect, and verifies root again. Installation
stops if no working root method is available.

The download is unpacked locally and checked for the selected ELF architecture.
The helper verifies the release asset's SHA-256 when GitHub provides one; older
releases may have no published digest. It pushes a uniquely named temporary file
to `/data/local/tmp`, sets root ownership and executable permissions, checks its
`--version`, and renames it to `frida-server` after validation.

After installation, the interactive shell should start as root in
`/data/local/tmp`. Check and start the server yourself:

```sh
id -u
pwd
./frida-server
```

Expect `0` and `/data/local/tmp` from the first two commands. Leave the server
running in that terminal, then open another host terminal and run the dumper:

```sh
.venv/bin/python dump_keys.py
```

Keep the host Python `frida` version matched to the server version. The helper
reports a mismatch when it can find the installed package; it does not change
the host environment. Choose `--ver` to match your installed Frida, or deliberately
update the host packages before using a newer server. Selecting an old server
version does not establish compatibility with this fork's current Frida APIs.

The helper does not start, stop, or restart Frida server processes. Replacing the
installed file does not update an already running server; stop that process
yourself before starting the newly installed version.

### Open only the device shell

For a device that is already prepared, or to inspect it manually:

```sh
.venv/bin/python tools/setup_frida.py --shell
.venv/bin/python tools/setup_frida.py --shell --device-id emulator-5554
```

This mode only selects the device, checks available shell privileges, and opens
an interactive shell in `/data/local/tmp`. It tries an existing root shell and
the supported `su` forms, then falls back to the normal ADB user if they fail.
It does not invoke `adb root` or restart the device's ADB daemon.

There is no architecture check, release lookup, download, upload, permission
change, or Frida startup in this mode. `--device-id` and `--adb` remain available;
`--shell` cannot be combined with `--no-shell`, `--ver`, or a manual `--arch`.
The fallback shell's permissions are those of the normal ADB user.

### Cleanup and maintainer checks

Downloads and unpacked binaries live in a temporary directory under the ignored
repository `tmp/`. They are removed after deployment, before entering the shell,
and on handled failures. A forcibly terminated process can leave files there;
they remain ignored. `.gitignore` also excludes `frida-server` and versioned
Android Frida server archives/binaries if downloaded elsewhere in the worktree.

On deployment failure, the helper attempts to remove only its uniquely named
temporary device file. Losing the ADB connection can prevent that cleanup. The
installed `/data/local/tmp/frida-server` is intentionally retained for use.

The focused tests use mocked ADB commands and synthetic release/download data:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_frida_setup.py' -v
```

The test module is [`tests/test_frida_setup.py`](../tests/test_frida_setup.py).

Live device installation, root-manager behavior, and the final interactive shell
still require manual verification on the target device.

<details>
<summary>🧪 Optional live-device checklist</summary>

On a test device, verify these paths:

1. Run the default setup command and confirm its reported ABI/architecture. In the
   resulting shell, check `id -u`, `pwd`, and `./frida-server --version`; expect
   root, `/data/local/tmp`, and the selected release. Start the server yourself
   when ready.
2. Run `--shell` on an already prepared device. Confirm the working directory and
   root access; on an unrooted device, confirm it opens with normal permissions.
3. With multiple online devices, confirm `--device-id` selects the intended one.
   Try a deliberately mismatched `--arch` and confirm it stops before uploading.
4. After setup, confirm its local `tmp/frida-*` download directory has been removed.

</details>

## Protobuf regeneration

[`regenerate_protobuf.py`](regenerate_protobuf.py) rebuilds the shipped
[`Helpers/wv_proto2_pb2.py`](../Helpers/wv_proto2_pb2.py) from the checked-in
[`Helpers/wv_proto2.proto`](../Helpers/wv_proto2.proto) and keeps its supported
Python runtime pin in [`requirements.txt`](../requirements.txt) aligned. Normal
users use the shipped binding and do not need to run this helper or install
`protoc`.

The schema has no imports, so all schema inputs needed for regeneration are
already in the repository. Do not edit the generated Python file by hand.
The schema origin and archive links remain in the
[Helpers source provenance](../Helpers/README.md#source-provenance).

### Regenerate or check the shipped binding

Use Python 3.10 or newer, install the project requirements into `.venv`, and have
the desired `protoc` compiler on `PATH`. The initial migration was validated with
`protoc 36.2` and Python `protobuf==7.36.2`. The generated file's header records
its required Python Protobuf version; `requirements.txt` records the shipped pin.

From the repository root:

```sh
.venv/bin/python tools/regenerate_protobuf.py --update-runtime
```

With no mode flag, the helper uses `protoc` from `PATH`, validates the generated
binding with the current Python environment, and replaces changed outputs. It
does not install packages. `--check` and `--update-runtime` are mutually
exclusive.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| *(no option)* | Regenerate, validate, and replace changed outputs. | Normal regeneration mode | `.venv/bin/python tools/regenerate_protobuf.py` |
| `-h`, `--help` | Show the complete helper help and exit. | — | `.venv/bin/python tools/regenerate_protobuf.py --help` |
| `--protoc PATH` | Use a specific `protoc` executable instead of the one found on `PATH`. | `protoc` | `.venv/bin/python tools/regenerate_protobuf.py --protoc /opt/homebrew/bin/protoc` |
| `--check` | Regenerate under ignored `tmp/` and compare the binding and runtime pin without replacing either; mutually exclusive with `--update-runtime`. | Off | `.venv/bin/python tools/regenerate_protobuf.py --check` |
| `--update-runtime` | Install the generated binding's exact Protobuf version in the virtual environment running the helper before updating tracked outputs; requires a virtual environment and is mutually exclusive with `--check`. | Off | `.venv/bin/python tools/regenerate_protobuf.py --update-runtime` |

With `--update-runtime`, the helper generates a temporary binding, reads its
Python Protobuf version, installs that exact runtime into the virtual environment,
validates the generated import, and updates both `Helpers/wv_proto2_pb2.py` and the exact Protobuf pin in
`requirements.txt`. Other dependencies are unchanged. It makes no Git commits.
Use `--protoc /path/to/protoc` to select a compiler explicitly.

Omit `--update-runtime` to regenerate using an already compatible environment.
The helper refuses to replace the output files if generation or import validation
fails. If the optional pip step succeeded before a later failure, the environment
remains updated; the helper does not downgrade it automatically.

To check the generated file and dependency pin without replacing either:

```sh
.venv/bin/python tools/regenerate_protobuf.py --check
```

This regenerates under ignored `tmp/` and compares the results byte for byte.
Use the same compiler version recorded in the last generation to reproduce the
checked-in output; changing compiler versions can change generated code even when
the schema is unchanged. `--check` never installs packages. All helper modes
resolve repository paths from the script, so they also work from another directory.

After regeneration, run the regression suite and dependency check:

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip check
```

[`tests/test_protobuf.py`](../tests/test_protobuf.py) checks the complete legacy schema, synthetic request bytes
serialized with the original binding and Protobuf 3.19.3, proto2 field presence,
unknown fields, and the dumper's certificate/key matching. It neither reads real
device captures nor writes key dumps. Intentional schema changes require reviewing
these compatibility expectations; a compiler/runtime update alone should preserve
them. Live device operation still needs a separate smoke test.
