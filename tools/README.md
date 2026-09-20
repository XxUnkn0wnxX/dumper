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
| 📦 [Optional WVD tooling](#optional-wvd-tooling) | Set up a separate environment for `pywidevine` and future WVD work. |

For schema origin and archive inventory, see [Helpers source provenance](../Helpers/README.md#source-provenance)
and the [archived WKS-KEYS protobuf sources](../archives/wks-keys/README.md).

## Frida server setup

[`setup_frida.py`](setup_frida.py) downloads an Android Frida server from the official
[Frida releases](https://github.com/frida/frida/releases), installs it as
`/data/local/tmp/frida-server`, opens a root terminal session in that directory,
and starts `./frida-server` automatically in the **foreground**. Its output stays
visible in that terminal. Keep the session open while using the dumper; press
**Ctrl+C** to stop Frida and return to a root shell in `/data/local/tmp`.
Use `--shell` to start the installed binary without downloading a replacement.

Use the helper for repeat test-device setups or to prepare several maintainer
devices one at a time. Device selection, architecture, and release version can
all be specified independently or combined in the same invocation.

The helper uses Python 3.10 or newer and the standard library. It requires an
online, rooted Android device or a root-capable emulator, plus ADB on the computer.
It does not root an unrooted device. **Every mode requires root**, including
`--shell`; if root is unavailable, the helper stops with setup guidance.

Before checking the cache or contacting GitHub, every mode asks `adb devices -l`
for an online target and requires at least one row whose state is exactly
`device`. This ADB transport requirement also applies to `--ver`, even when a
matching archive is already cached; it is not a request to mount or inspect host
storage. If no eligible row exists, the helper stops before target checks, cache
work, release lookup, download, installation, or shell handoff.

> [!IMPORTANT]
> **Wait for Android to finish booting before running this helper or the dumper.**
> Unlock the phone or emulator and confirm its home screen is visible and
> responsive. ADB can report an attached device with state `device` before boot
> finishes. The helper's online-device check does not verify that Android's home
> screen or services are ready; check the device screen before continuing.

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

Both normal installation and `--shell` try `adb root` if existing root and `su`
are unavailable. On a physical device, arrange working root access through `su`
before using the helper.

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

Wait until Android has finished booting and its unlocked home screen is visible
and responsive. Enable USB debugging when using a physical device and accept
its authorization prompt. An online ADB entry looks like:

```text
List of devices attached
emulator-5554  device
```

Only entries whose state is exactly `device` are eligible. Entries marked
`offline`, `unauthorized`, or another state are skipped. With multiple online
devices, select one explicitly using `--device-id`.

<details>
<summary>🧩 Optional ADB through pip</summary>

The optional [adbutils wheels](https://pypi.org/project/adbutils/) provide the
native ADB executable and its companion files through a third-party Python
package. They cover the ADB executable needed by this helper; other Android SDK
tools are installed separately. To add this fallback to the same virtual
environment used by the helper, from the repository root run:

```sh
.venv/bin/python -m pip install -r tools/requirements-adb.txt
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.
The [optional ADB requirements file](requirements-adb.txt) pins the tested
version and requires a wheel, so pip does not fall back to a source distribution
without a bundled executable. Published
wheels currently cover Windows x86/x64, Linux x86_64, and Intel macOS. There is
no native ARM-host wheel for pinned `adbutils==2.12.0`; use system Android SDK
Platform-Tools on those hosts.

By default, the helper searches for `adb` on `PATH` first, then the bundled
`adb` binary in the helper's Python environment (`adb.exe` on Windows). Pass
`--adb PATH` when a specific executable must win over both choices; an invalid
explicit path fails rather than falling back. The helper never installs pip
packages automatically, and the optional package is not part of the dumper's
regular requirements. It locates the packaged binary directly and does not
create a standalone `adb` shell command. Startup prints `Using ADB: ...`, so the
selected executable path is visible. The `adbutils` package version and the
version reported by its bundled ADB executable are separate version numbers.
If neither PATH nor the bundled fallback is available, setup stops before device
lookup and prints the requirements install command; run it with the same Python
environment used to invoke the helper.

</details>

### Install and open the device shell

From the repository root, in an interactive terminal:

```sh
.venv/bin/python tools/setup_frida.py
```

This checks for the latest stable Frida release and detects the server
architecture from Android's primary CPU ABI before selecting a download or
matching [cached archive](#download-cache-and-cleanup):

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
| `--ver VERSION` | Use a specific `X.Y.Z` Frida release. Reuses its valid cached archive without network access, or downloads it if missing. | Latest stable release, with cached fallback on network failure | `.venv/bin/python tools/setup_frida.py --ver 16.3.3` |
| `--arch {auto,x86_64,x86,arm64,arm}` | Detect the primary ABI with `auto`, or select one of the four explicit architectures; an explicit choice must match the device's primary ABI. | `auto` | `.venv/bin/python tools/setup_frida.py --arch arm64` |
| `--device-id SERIAL`, `-s SERIAL` | Select an online ADB device explicitly. | The only online `device` entry | `.venv/bin/python tools/setup_frida.py --device-id emulator-5554` |
| `--adb PATH` | Use a specific `adb` or `adb.exe` executable. | `adb` on `PATH`, then an `adbutils` bundled binary | `.venv/bin/python tools/setup_frida.py --adb /opt/android/platform-tools/adb` |
| `--no-shell` | Replace and run Frida in the foreground, then return to the host when it stops, without a subsequent interactive root prompt. Mutually exclusive with `--shell`. | Off; the default flow leaves a root prompt after Frida stops | `.venv/bin/python tools/setup_frida.py --no-shell` |
| `--shell` | Run the installed server in the foreground, or just open `/data/local/tmp` if absent. Restarts an existing managed process into this terminal. Requires root and performs no download or replacement; mutually exclusive with `--no-shell`, `--ver`, and a manual (non-`auto`) `--arch`. | Off | `.venv/bin/python tools/setup_frida.py --shell` |

The helper first checks whether the ADB shell is already root. Otherwise it tries
`su -c` and the emulator-style `su 0 sh -c`. Approve any root-manager prompt on
Android. If neither works, it tries `adb root`, which can restart the device's ADB
daemon, waits for that device to reconnect, and verifies root again. Both setup
and `--shell` stop if no working root method is available. For an emulator, use
the debug-image guidance above; a physical device needs working root/`su` access.

The download is unpacked locally and checked for the selected ELF architecture.
The helper verifies the release asset's SHA-256 when GitHub provides one; older
releases may have no published digest. It pushes a uniquely named temporary file
to `/data/local/tmp`, sets root ownership and executable permissions, checks its
`--version`, stops the previous server at the managed path, and renames the
validated binary to `frida-server`. It then hands the terminal to ADB. ADB
enters `/data/local/tmp` in a root terminal session and prints a launch line like:

```text
generic_x86_64:/data/local/tmp # ./frida-server
```

On macOS and Linux, the host Python process hands the terminal to ADB and is
replaced before this line appears; Python does not poll or wait around the
session. On Windows, Python owns a direct ADB child only as a status-preserving
compatibility shim: ADB inherits the terminal, the healthy session has no
overall timeout, and Python waits until ADB exits. If the Windows ADB session
ends nonzero, setup reports the exit status without assuming that it proves a
device disconnect; reconnect the device if needed and inspect the ADB/Frida
output before retrying. Host Ctrl+C or a wait error performs bounded child
termination/reaping so a cancelled setup does not intentionally leave its ADB
child behind. The line is a launch indication, not an idle prompt. The server
has **no startup timeout** and does not use `--daemonize`, so its output and
startup errors remain visible while ADB waits for it to exit. In the default
mode and `--shell`, press **Ctrl+C** in this terminal to stop Frida; the real
root prompt appears only after Frida exits. Native Windows terminal behavior
remains unverified.
Keep that terminal open and run the dumper from a second host terminal:

```sh
.venv/bin/python dump_keys.py
```

Every normal setup run installs and replaces the server, even if the selected
version is already installed. It reuses a matching cached archive when available,
as described below. Replacing a running server interrupts active Frida
sessions. The helper identifies it by the exact executable path under `/proc`,
sends `SIGTERM`, and waits for it to stop. If it does not stop, setup fails; it
does not force-kill it or terminate an unrelated process using the same port.

When finished, stop Frida with **Ctrl+C** in its terminal. The default flow and
`--shell` then leave a root prompt in `/data/local/tmp`, where you can check:

```sh
id -u
pwd
./frida-server --version
```

Expect `0` and `/data/local/tmp` from the first two commands. Enter `./frida-server`
at that prompt to start it again manually. With the direct or `adb root` route,
one `exit` returns to the host. With `su-c` or `su-0`, the root prompt is nested
inside the ordinary ADB shell, so the first `exit` returns to that ADB shell and
the second `exit` returns to the host. `--no-shell` has no follow-up prompt: ADB
exits with Frida's status when the foreground server stops.

Keep the host Python `frida` version matched to the server version. The helper
reports a mismatch when it can find the installed package; it does not change
the host environment. Choose `--ver` to match your installed Frida, or deliberately
update the host packages before using a newer server. Selecting an old server
version does not establish compatibility with this fork's current Frida APIs.

Use `--no-shell` when you want the helper to exit after the foreground server
stops, without leaving an interactive root prompt. It also supports redirected
input/output. It waits while Frida runs; it does not start a background service.
The default mode and `--shell` require an interactive terminal.

### Reuse the installed server and open a shell

For a device that is already prepared, or to inspect it manually:

```sh
.venv/bin/python tools/setup_frida.py --shell
.venv/bin/python tools/setup_frida.py --shell --device-id emulator-5554
```

This is the helper's launch mode for a device that is already prepared. After
verifying root access, it checks `/data/local/tmp/frida-server`:

| Installed state | `--shell` behavior |
| --- | --- |
| Executable present and stopped | Starts it in the foreground of the root terminal. |
| Server already running from the managed path | Gracefully stops that instance, then starts the installed binary in the foreground of this terminal. |
| File absent and no managed server running | Opens a root shell in `/data/local/tmp`. |
| File absent but an old managed process remains | Reports the orphaned process and opens a root shell without launching another server. |
| Invalid installation or startup failure | Reports the error and stops. |

There is no architecture check, release lookup, download, upload, permission
change, or replacement in this mode. `--device-id` and `--adb` remain available;
`--shell` cannot be combined with `--no-shell`, `--ver`, or a manual `--arch`.
It uses the same root checks as installation, including the `adb root` fallback.
Restarting an existing server interrupts its active Frida sessions. An already
running background process cannot be moved into this terminal; the helper starts
a fresh foreground process using the installed executable.

### Download cache and cleanup

Downloaded archives are kept beside this helper in **`tools/.cache/frida/`**.
Each `.xz` filename includes its version and architecture, so repeat setups and
explicit `--ver` / `--arch` combinations can reuse their own downloads.
A small companion `.json` records the archive's checksum for later integrity
checks without network access. Keep it with its archive when copying the cache.
The existing `.gitignore` rule excludes this cache from commits.

| Invocation / network state | Archive selection |
| --- | --- |
| `--ver 16.3.3` with a valid matching archive | Uses that cached version without a network request. |
| `--ver 16.3.3` without a usable matching archive | Looks up and downloads exactly that version; stops if it cannot obtain it. |
| No `--ver` | Checks the latest stable release on each run, reuses its cached archive when available, or downloads it. |
| Latest-release lookup or download fails | Reports the failure and uses the newest valid cached version for the device's architecture; stops if there is none. |
| `--shell` | Uses the installed device binary and does not access GitHub or the cache. |

Release lookups and new downloads have a **30-second network timeout**. Cached
archives are validated and unpacked locally, without a download timeout; the
foreground Frida session also has no timeout. The helper prints the version it
selects and installs, including when it falls back to an older cached release.
An explicit `--ver` never falls back to a different version.

Only fully downloaded and validated archives become reusable cache entries.
Interrupted downloads are not reused. Unpacked executables live in a temporary
directory under the ignored repository `.tmp/`; they are removed after deployment,
before entering the shell, and on handled failures. A new download also uses a
temporary directory inside the cache to validate the executable before publishing
the archive; that directory is removed too. The `.xz` and its checksum record
remain cached even if device deployment fails. A forcibly terminated helper can
leave temporary files behind; those remain ignored. You may remove cached
archives and their companion records to reclaim space; the next setup that needs
them downloads them again.

The helper creates `.tmp/` and `tools/.cache/frida/` automatically when needed.
Fresh checkouts require no manual folder creation or files from a maintainer's
scratch directory. Repository `.tmp/` is disposable and may be deleted between
runs: no required source, schema, tests, configuration, or reusable downloads
are stored there. Reusable tests are shipped in `tests/`. The separate `tmp/`
folder remains ignored for local developer scratch work; neither helper uses it.

`.gitignore` also excludes `frida-server` and versioned Android Frida server
archives/binaries if downloaded elsewhere in the worktree.

On deployment failure, the helper attempts to remove only its uniquely named
temporary device file. Losing the ADB connection can prevent that cleanup. The
installed `/data/local/tmp/frida-server` is intentionally retained for use.

### Maintainer checks

The focused tests use mocked ADB commands and synthetic release/download data.
The terminal tests use local fake programs and PTYs; they never contact Android.
They verify that the POSIX ADB handoff keeps the same process identity, that the
Windows compatibility handoff preserves ADB status and Ctrl+C, that `su-c` and
`su-0` need two exits after the root prompt while direct/`adb root` needs one, and
that setup errors return without opening a follow-up shell:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_frida_setup.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_frida_terminal.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_readme_docs.py' -v
```

| Test module | Coverage |
| --- | --- |
| [`test_frida_setup.py`](../tests/test_frida_setup.py) | Device selection, root checks, installation, cache integrity, network failures, and cleanup. |
| [`test_frida_terminal.py`](../tests/test_frida_terminal.py) | ADB handoff in the same process, foreground terminal input/output, Ctrl+C, nested `su-c`/`su-0` exits, the remaining shell's directory, and error exit statuses. Skipped on Windows because it uses POSIX PTYs. |
| [`test_readme_docs.py`](../tests/test_readme_docs.py) | Local README links, markup, navigation, and command argument tables. |

To include the optional 31-second foreground lifetime test on macOS or Linux:

```sh
FRIDA_TEST_LONG_SESSION=1 .venv/bin/python -m unittest discover -s tests -p 'test_frida_terminal.py' -v
```

The earlier installation/manual-start workflow was reported working on Android
9 / API 28 on 2026-09-20. A subsequent background-start implementation timed out
on Android 10 / API 29; it has been replaced with foreground terminal startup.
The corrected startup and replacement behavior still needs live verification.
Mocked tests cover these flows, root refusal, startup failures, and selecting only
the process at the managed executable path. Local POSIX terminal tests also
exercise Ctrl+C and the following shell for all supported root command forms;
the complete foreground Frida lifecycle, other Android/root-manager combinations,
and disconnected-device behavior still need device testing. A separate shell-only
`su-0` handoff check on an Android 10 / API 29 emulator verified the root prompt,
`/data/local/tmp`, and the two-exit return through the ordinary ADB shell; it did
not exercise Frida foreground startup or replacement.

<details>
<summary>🧪 Optional live-device checklist</summary>

On a test device, verify these paths:

1. Run the default setup command and confirm its reported ABI/architecture. Frida
   should print its launch indication and run in the foreground with live output.
   The launch line is not an idle prompt. Leave it running for more than 30
   seconds and confirm the dumper connects from a second host terminal. Press
   Ctrl+C, then check `id -u`, `pwd`, and `./frida-server --version` at the
   resulting prompt; expect root, `/data/local/tmp`, and the selected release.
   With `su-c` or `su-0`, use a second `exit` to close the ordinary ADB shell;
   direct/`adb root` needs one `exit`.
2. Re-run setup on an idle test device; confirm the server is replaced and starts
   again. Check that `--no-shell` keeps Frida in the foreground and returns to the
   host only after it stops, without leaving a root prompt.
3. Run `--shell` with an installed but stopped server, then again while it is
   running. Confirm the latter restarts the managed server into the new terminal.
   On a fresh rooted device without the installed file, confirm it opens the
   directory only.
4. On a device without working `su` or `adb root`, confirm both modes stop with
   root/image guidance instead of opening an unprivileged shell.
5. With multiple online devices, confirm `--device-id` selects the intended one.
   Try a deliberately mismatched `--arch` and confirm it stops before uploading.
6. After setup, confirm its local `.tmp/frida-*` directory has been removed and
   the `.xz` remains in `tools/.cache/frida/`. Repeat the same version and confirm
   the helper reports using the cache. Verify `--ver` works from that cache with
   the computer offline; default mode should report its failed latest-release
   check and use the newest valid cached version for the detected architecture.
   Keep an ADB `device` online while making the computer's GitHub/network path
   unavailable: the cache can avoid release/download traffic, but it cannot
   bypass the online-device gate.

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
| `--check` | Regenerate under ignored `.tmp/` and compare the binding and runtime pin without replacing either; mutually exclusive with `--update-runtime`. | Off | `.venv/bin/python tools/regenerate_protobuf.py --check` |
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

This regenerates under ignored `.tmp/` and compares the results byte for byte.
The helper creates `.tmp/` automatically and removes its temporary working
directory afterward; no scratch files or manual initialization are required.
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

## Optional WVD tooling

[`requirements-wvd.txt`](../requirements-wvd.txt) provides
[`pywidevine`](https://pypi.org/project/pywidevine/) for future work with Widevine
device (`.wvd`) files. This is optional preparation; the dumper currently writes
`client_id.bin` and `private_key.pem`, and automatic WVD creation is not implemented.

> [!IMPORTANT]
> **Use a separate virtual environment.** `pywidevine` 1.9.0 requires
> `protobuf>=6.33.0,<7.0.0`, while the dumper's shipped binding requires
> `protobuf==7.36.2`. Do not install both requirements files into the same
> environment or bypass dependency checks with `--no-deps`.

| Purpose | Environment | Requirements |
| --- | --- | --- |
| Run the dumper or regenerate its binding | `.venv` | [`requirements.txt`](../requirements.txt) |
| Use `pywidevine` for WVD work | `.venv-wvd` | [`requirements-wvd.txt`](../requirements-wvd.txt) |

From the repository root, create the optional environment with Python 3.10 or
newer and install only its requirements:

```sh
python3 -m venv .venv-wvd
.venv-wvd/bin/python -m pip install --upgrade -r requirements-wvd.txt
.venv-wvd/bin/python -m pip check
.venv-wvd/bin/pywidevine --help
```

<details>
<summary>🪟 Windows PowerShell setup</summary>

```powershell
py -3 -m venv .venv-wvd
.venv-wvd\Scripts\python.exe -m pip install --upgrade -r requirements-wvd.txt
.venv-wvd\Scripts\python.exe -m pip check
.venv-wvd\Scripts\pywidevine.exe --help
```

</details>

These commands use each environment directly, so activation is optional. Run the
dumper with `.venv/bin/python` and WVD tooling with `.venv-wvd/bin/python` or
`.venv-wvd/bin/pywidevine` (the corresponding `Scripts` paths on Windows).
The optional requirement is unpinned so pip can resolve compatible releases within
that environment. `.venv-wvd/` is ignored by Git.
