# 🧰 Frida server setup

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [📱 Android setup](android-setup.md) · [🤖 Full-auto](full-auto.md) · [🧪 Testing](testing.md)

[`tools/setup_frida.py`](../tools/setup_frida.py) downloads an Android Frida
server from the official [Frida releases](https://github.com/frida/frida/releases),
installs it as `/data/local/tmp/frida-server`, and starts it in the **foreground**
of a root terminal session. Keep that terminal open while using the dumper. Use
`--shell` to start an installed binary without downloading a replacement.

The helper uses Python 3.10 or newer and the standard library, and invokes pip
when the host Frida package needs to be installed or synchronized. It requires an
online, rooted Android device or root-capable emulator plus ADB on the computer;
it does not root an unrooted device. Every mode requires root, including
`--shell`. Complete ADB, emulator-image, and authorization instructions are in
the [Android setup guide](android-setup.md).

When invoked outside a venv, shared startup first
[initializes and enters `.venv`](setup.md#automatic-environment-setup). An
already active venv with any name is accepted. This host dependency setup can
run before device discovery; downloading or deploying the Android server still
requires an online device.

## Frida server setup

From the repository root, with the environment from [Python setup](setup.md)
active, run the default interactive setup:

```sh
python tools/setup_frida.py
```

On Windows PowerShell, use `python tools\setup_frida.py` after activating
`.venv`, or invoke `.venv\Scripts\python.exe tools\setup_frida.py` directly.

Before checking the cache or contacting GitHub, every mode asks `adb devices -l`
for an online target and requires at least one row whose state is exactly
`device`. This requirement also applies to `--ver`, even when an archive is
cached. If no eligible row exists, the helper stops before target checks, cache
work, release lookup, download, installation, or shell handoff. Immediately
before uploading a downloaded or cached server, it checks that the **same
selected device** still reports `device`; a disconnect stops setup before the
file is sent.

The helper detects the server architecture from Android's primary CPU ABI:

| Android primary ABI | Frida server architecture |
| --- | --- |
| `x86_64` | `x86_64` (64-bit Intel/AMD) |
| `x86` | `x86` (32-bit Intel/AMD) |
| `arm64-v8a` | `arm64` (64-bit ARM) |
| `armeabi-v7a` | `arm` (32-bit ARM) |

For example, an x86_64 emulator receives the x86_64 build, while a physical
Pixel 6 Pro receives the ARM64 build. You can select an architecture, release,
or device explicitly:

```sh
python tools/setup_frida.py --arch arm64
python tools/setup_frida.py --ver 16.3.3
python tools/setup_frida.py --device-id emulator-5554
python tools/setup_frida.py --device-id emulator-5554 --arch x86_64 --ver 16.3.3
```

On Windows, an explicit ADB path looks like:

```powershell
python tools\setup_frida.py --ver 16.3.3 --device-id emulator-5554 --adb "C:\Android\platform-tools\adb.exe"
```

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| `-h`, `--help` | Show the complete helper help and exit. | — | `python tools/setup_frida.py --help` |
| `--ver VERSION` | Use a specific `X.Y.Z` server release and synchronize the host package to it, including downgrades. A valid cached server archive avoids its download; a host package change may still need pip network access. | Latest stable release, with cached fallback on network failure | `python tools/setup_frida.py --ver 16.3.3` |
| `--arch {auto,x86_64,x86,arm64,arm}` | Detect the primary ABI with `auto`, or select one of the four explicit architectures; an explicit choice must match the device's primary ABI. | `auto` | `python tools/setup_frida.py --arch arm64` |
| `--device-id SERIAL`, `-s SERIAL` | Select an online ADB device explicitly. | The only online `device` entry | `python tools/setup_frida.py --device-id emulator-5554` |
| `--adb PATH` | Use a specific `adb` or `adb.exe` executable. | `adb` on `PATH`, then an `adbutils` bundled binary | `python tools/setup_frida.py --adb /opt/android/platform-tools/adb` |
| `--no-shell` | Replace and run Frida in the foreground, then return to the host when it stops, without a subsequent interactive root prompt. Mutually exclusive with `--shell`. | Off; the default flow leaves a root prompt after Frida stops | `python tools/setup_frida.py --no-shell` |
| `--non-interactive` | Internal alias for `--no-shell`, reserved for `full_auto.py`, which supplies it automatically. Use `--no-shell` for manual runs. | Off | Set by `python full_auto.py` |
| `--shell` | Run the installed server in the foreground, or just open `/data/local/tmp` if absent. Synchronizes the host package before restarting an existing managed server. Requires root; never downloads or replaces the Android server. Mutually exclusive with `--no-shell`, `--ver`, and a manual (non-`auto`) `--arch`. | Off | `python tools/setup_frida.py --shell` |

The helper first checks whether the ADB shell is already root. Otherwise it tries
`su -c` and the emulator-style `su 0 sh -c`; if neither works, it tries `adb
root`, waits for that device to reconnect, and verifies root again. Both setup and
`--shell` stop if no working root method is available.

The download is unpacked locally and checked for the selected ELF architecture.
The helper verifies the release asset's SHA-256 when GitHub provides one; older
releases may have no published digest. After synchronizing the host Python
package as described below, it pushes a uniquely named temporary file
to `/data/local/tmp`, sets root ownership and executable permissions, checks its
`--version`, stops the previous server at the managed path, and renames the
validated binary to `frida-server`.

## Host Python package synchronization

The **actual server selected for deployment** determines the required Python
`frida` version. That can be the latest release, an explicit `--ver`, or an
older archive selected by cache fallback. In `--shell` mode, the installed
Android binary's reported version is used before stopping or restarting it.
If no installed server can be launched, opening the shell does not invoke pip.

Frida's [protocol error handling](https://github.com/frida/frida-core/blob/main/lib/base/session.vala)
calls for matching major versions and support for the requested features. This
project uses an exact release match for a predictable setup. `frida-tools` has
its own version number; pip selects a release compatible with the chosen
`frida` package.

When versions differ, the helper prints a warning and explicitly reports
**Automatically upgrading**, **Automatically downgrading**, or
**Automatically installing**, including the current and target versions. A
matching installation skips the package update. **Automatic package changes
require a virtual environment.** Package commands use that environment's Python
interpreter, so run setup and the dumper from the same environment. Normal CLI
startup automatically enters `.venv` when necessary; the package-sync function
also guards against being called outside any venv. It never attempts a global
package update. Pip destination settings must not redirect installation outside
that environment, and settings that bypass dependency resolution are rejected.

Before changing packages, the helper requires a successful `pip check` and a
resolver dry run. Existing packages other than `frida` and `frida-tools` are
held at their installed versions, so a conflicting update stops before
installation. New dependencies may be added when needed. After installation,
a fresh Python process must import the exact selected Frida release, and
`pip check` must pass again before device deployment or server startup.

Missing pip, an unavailable Frida wheel, dependency conflicts, or an update
failure stop setup with guidance. The helper does not upgrade pip itself or
bypass the virtual-environment guard. A cached Android archive avoids
the server download, but synchronizing Python packages may still need network
access. Selecting an old server does not guarantee support for the host's
Python version or this fork's Frida APIs.

## Foreground operation and Ctrl+C

The shared CLI startup repairs a POSIX terminal left in raw mode by an earlier
ADB session. It restores normal newline handling and `Ctrl+C` signal settings on
POSIX ttys; redirected streams and native Windows consoles are left unchanged.

After installation, ADB enters `/data/local/tmp` in a root terminal session and
prints a launch line such as:

```text
generic_x86_64:/data/local/tmp # ./frida-server
```

On macOS and Linux, the host Python process hands the terminal to ADB and is
replaced before this line appears. On Windows, Python owns a direct ADB child as
a status-preserving compatibility shim; ADB inherits the terminal, a healthy
session has no overall timeout, and Python waits until ADB exits. The launch line
is not an idle prompt. The server has no startup timeout and does not use
`--daemonize`, so output and startup errors remain visible.

In the default mode and `--shell`, press **Ctrl+C** in this terminal to stop
Frida; the root prompt appears after Frida exits. If shutdown stalls, the Android
shell warns and sends `SIGKILL` after five seconds, checking the original child
PID and process start time first. This fallback applies only to the server
launched by this helper session; it does not kill ADB or scan unrelated
processes. Normal operation has no runtime limit. Native Windows terminal
behavior remains unverified.

Keep that terminal open and run the dumper from a second host terminal:

```sh
python dump_keys.py
```

Every normal setup run installs and replaces the server, even if the selected
version is already installed. Replacing a running server interrupts active Frida
sessions. The helper identifies it by the exact executable path under `/proc`,
sends `SIGTERM`, and waits for it to stop; it does not force-kill an unrelated
process using the same port.

When finished, stop Frida with **Ctrl+C**. The default flow and `--shell` leave a
root prompt in `/data/local/tmp`:

```sh
id -u
pwd
./frida-server --version
```

Expect `0` and `/data/local/tmp` from the first two commands. With direct or
`adb root`, one `exit` returns to the host. With `su-c` or `su-0`, the first
`exit` returns to the ordinary ADB shell and the second returns to the host.
`--no-shell` has no follow-up prompt: ADB exits with Frida's status, or status
`130` if its Ctrl+C fallback had to force-stop it. The full-auto controller
supplies its internal `--non-interactive` alias when starting setup, waits for
Frida readiness, and then launches its dumper worker. Manual setup should use
the documented `--no-shell` option instead.

## Reuse the installed server and open a shell

For a prepared device or manual inspection:

```sh
python tools/setup_frida.py --shell
python tools/setup_frida.py --shell --device-id emulator-5554
```

After verifying root access, `--shell` checks `/data/local/tmp/frida-server`:

| Installed state | `--shell` behavior |
| --- | --- |
| Executable present and stopped | Starts it in the foreground of the root terminal. |
| Server already running from the managed path | Gracefully stops that instance, then starts the installed binary in the foreground. |
| File absent and no managed server running | Opens a root shell in `/data/local/tmp`. |
| File absent but an old managed process remains | Reports the orphaned process and opens a root shell without launching another server. |
| Invalid installation or startup failure | Reports the error and stops. |

This mode skips architecture checks and server release/cache work. It never
downloads, uploads, changes permissions on, or replaces the Android binary.
Host Python packages may be synchronized before startup. `--device-id` and `--adb` remain available;
`--shell` cannot be combined with `--no-shell`, `--ver`, or a manual `--arch`.
An already running background process cannot be moved into this terminal; the
helper starts a fresh foreground process using the installed executable.

## Download cache and cleanup

Downloaded archives are kept in **`tools/.cache/frida/`**. Each `.xz` filename
includes its version and architecture, and a companion `.json` records the
archive checksum. The cache is ignored by Git.

| Invocation / network state | Archive selection |
| --- | --- |
| `--ver 16.3.3` with a valid matching archive | Uses that cached server archive without a release lookup or download. |
| `--ver 16.3.3` without a usable matching archive | Looks up and downloads exactly that version; stops if it cannot obtain it. |
| No `--ver` | Checks the latest stable release on each run, reuses its cached archive when available, or downloads it. |
| Latest-release lookup or download fails | Reports the failure and uses the newest valid cached version for the device's architecture; stops if there is none. |
| `--shell` | Uses the installed device binary without server release or cache work. |

Release lookups and new downloads have a **30-second network timeout**. Cached
archives are validated and unpacked locally, without a download timeout; the
foreground Frida session also has no timeout. An explicit `--ver` never falls
back to another version.

Only fully downloaded and validated archives become reusable cache entries.
Interrupted downloads are not reused. Unpacked executables live in ignored
`.tmp/` staging directories and are removed after deployment, before entering a
shell, and on handled failures. A new download validates the executable in a
temporary cache directory before publishing the archive. The `.xz` and checksum
record remain cached even if device deployment fails. A forcibly terminated
helper can leave ignored temporary files behind.

The helper creates `.tmp/` and `tools/.cache/frida/` automatically. Fresh
checkouts need no scratch files from a maintainer. `.tmp/` is disposable and
contains no required source, schema, tests, or configuration. The installed
`/data/local/tmp/frida-server` is intentionally retained after deployment
failure; cleanup can be prevented by an ADB disconnect.

## Cancellation and cleanup

During setup, **Ctrl+C** while checking devices, resolving a release, downloading
or extracting an archive, synchronizing Python packages, validating a candidate,
or uploading it starts cleanup before exit. The helper removes its local
temporary staging tree; if an upload
was interrupted, it attempts to remove only this run's uniquely named partial
remote upload, with a three-second bound and a warning if that owned cleanup
cannot finish. It then returns status `130` and does not continue to a later
deployment step. This also cleans incomplete downloads and extracted binaries
when cancellation happens before upload starts. Complete cache archives and
the installed server are retained.

Pip package changes are not a transaction that the helper can roll back. If an
installation is interrupted or fails partway through, inspect the reported
error and repair the Python environment before retrying. The helper will not
continue into device deployment after that failure.

## Maintainer checks

Managed-server checks inspect `/proc/PID/exe` links in one batch. Exact executable
paths, including deleted mappings, determine ownership; each candidate is
rechecked immediately before `SIGTERM`. Setup-command timeouts report the failed
stage without dumping generated shell code. An unreadable process listing stops
setup rather than being treated as proof that no server exists.

Foreground shutdown uses an interruptible Android shell `wait`. A normal
foreground command makes Android `mksh` defer its INT trap until the command
exits, which cannot recover from a stuck shutdown. The helper keeps job control
disabled and attaches its child to the same foreground terminal process group,
with inherited input and output. Ctrl+C reaches Frida normally; the shell can
enforce the shutdown deadline. No host polling or background daemon is added.
The process start-time check uses only that child's `/proc/PID/stat` and skips
zombies, unreadable identities, and reused PIDs.

The focused tests use mocked ADB commands and synthetic release/download data.
Terminal tests use local fake programs and PTYs; they never contact Android:

```sh
python -m unittest discover -s tests -p 'test_frida_setup.py' -v
python -m unittest tests.test_bootstrap tests.test_frida_host_sync tests.test_frida_cancellation -v
python -m unittest discover -s tests -p 'test_frida_process_scan.py' -v
python -m unittest discover -s tests -p 'test_frida_process_identity.py' -v
python -m unittest discover -s tests -p 'test_frida_terminal.py' -v
```

They cover environment initialization, host Frida upgrade/downgrade selection,
venv and dependency guards, device selection, root checks, installation, cache
integrity, network failures, exact managed-process identity, foreground terminal
input/output, Ctrl+C, bounded shutdown, nested `su-c`/`su-0` exits, and error statuses. The
terminal tests are skipped on Windows because they use POSIX PTYs.

The earlier manual-start workflow was reported working on Android 9 / API 28.
A background-start implementation timed out on Android 10 / API 29 and was
replaced with foreground startup. On Android 11 / API 30 x86_64 with Frida
17.18.0 and `su-0`, a live test reproduced a server that disconnected the
dumper after Ctrl+C but stalled during its own shutdown; the five-second fallback
stopped it, returned a root prompt in `/data/local/tmp`, and preserved both shell
exits. Replacement, other Android/root-manager combinations, native Windows
terminals, and device/ADB loss still need live testing.
Automatic Python package changes are covered with mocked pip commands;
upgrade/downgrade compatibility on each real host still needs confirmation.

<details>
<summary>🧪 Optional live-device checklist</summary>

On a test device, verify these paths:

1. Run the default setup and confirm its ABI, foreground launch indication, and
   live output. Leave it running for more than 30 seconds and connect the dumper
   from a second terminal. Press Ctrl+C, then check `id -u`, `pwd`, and
   `./frida-server --version`; expect root, `/data/local/tmp`, and the selected
   release. Repeat with the dumper attached and confirm its clean disconnect.
2. Re-run setup on an idle device and confirm replacement. Check that `--no-shell`
   stays foreground and returns to the host without leaving a root prompt.
3. Run `--shell` with an installed stopped server and while it is running. Confirm
   the latter restarts the managed server in the new terminal. On a fresh rooted
   device without the file, confirm it opens the directory only.
4. On a device without working `su` or `adb root`, confirm both modes stop with
   root/image guidance rather than opening an unprivileged shell.
5. With multiple online devices, confirm `--device-id` selection and reject a
   deliberately mismatched `--arch` before upload.
6. Confirm `.tmp/frida-*` is removed and the `.xz` remains in
   `tools/.cache/frida/`. Repeat the same version to confirm cache reuse. With an
   ADB `device` online, make the GitHub/network path unavailable and confirm
   default mode falls back to the newest valid cached architecture entry.

</details>
