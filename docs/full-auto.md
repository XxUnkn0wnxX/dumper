# 🤖 Experimental full-auto workflow

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🧩 Dumper operation](dumper.md) · [🧰 Frida setup](frida-setup.md)

`full_auto.py` is an experimental controller for one Frida setup and one
automatic dumper capture. It is intended for a rooted Android 9–13 target
(API 28–33) that is already authorized, fully booted, and ready for playback.
The API range is a gate, not a compatibility claim: a run still needs a
successful automatic `PrepareKeyRequest` signature hook before capture can
work.

## Run from the repository root

Initialize the checkout first, then start the controller:

```sh
python3 init.py
python3 full_auto.py
```

In Windows PowerShell, use:

```powershell
py -3 init.py
py -3 full_auto.py
```

Shared startup checks for an already active custom virtual environment first;
otherwise it creates or reuses the repository `.venv`. It installs or repairs
requirements only when the selected environment needs them. Running `init.py`
first makes that preparation and any dependency errors visible before device
work. The controller launches both child CLIs from the repository root.
Normal use needs no compile step or `protoc`; the generated protobuf module is
already included. See [protobuf maintenance](protobuf.md) only if regenerating it.

Even when invoked directly, `full_auto.py` first runs shared initialization and
bootstrap as an owned background job. All of that job's output goes to
`logs/init.log`; the controller waits for it to finish, then checks the active
environment and requirements before starting device work. The three stages are
initialization, Frida, and dumper: initialization exits before the two live
capture children run together. Frida starts first, and the controller checks
its owned process record and makes a fresh connection before launching the
dumper.

The dumper uses the same browser launcher as a manual run: it force-stops Chrome
on the selected Android device before opening the test URL for a fresh launch.
It applies the shared [Chrome onboarding and autoplay settings](chrome.md);
that guide lists every setting, compatibility limits, and how to undo them.

The two capture children run in the background with each child's raw stdout and
stderr redirected to its fixed log. The original terminal shows controller
progress, results, and log paths. It does not open new windows or tabs,
automate a GUI, select a terminal application, or require UI access
permissions. The parent retains each child process handle and signals only
those owned children during cleanup.
The dumper is invoked in strict automatic mode and does not accept a CDM
version or function-name override.

## Controller arguments

Run `python3 full_auto.py --help` for the installed command's help. These are
the supported controller options:

| Argument | Purpose | Default | Example |
| --- | --- | --- | --- |
| `-h`, `--help` | Show the controller help and exit. | — | `python3 full_auto.py --help` |
| `--device-id SERIAL`, `-s SERIAL` | Select the same authorized Android device for ADB and Frida. | The single online device; required if several are online. | `python3 full_auto.py --device-id emulator-5554` |
| `--adb PATH` | Select the `adb` or `adb.exe` executable passed to the workers. | `adb` on `PATH`, then the bundled fallback. | `python3 full_auto.py --adb /opt/android/platform-tools/adb` |
| `--ver VERSION` | Select the Frida server release and matching host package. | The Frida setup helper's normal release selection. | `python3 full_auto.py --ver 17.18.0` |
| `--startup-timeout SECONDS` | Bound initialization, Frida readiness, and dumper hook setup separately. This does not time out healthy playback or permission waiting. | `600` seconds | `python3 full_auto.py --startup-timeout 900` |

There is no `--cdm-version` or `--function-name` option in `full_auto.py`.
Those advanced manual-layout controls remain available on direct
`dump_keys.py` runs; see the [dumper guide](dumper.md#layout-detection-and-options).

The child scripts' `--non-interactive` flag is reserved for `full_auto.py`, which
supplies it automatically to both Frida setup and the dumper. Omit it when running
either script manually; use `--no-shell` for manual Frida setup without a follow-up
root prompt.

## Capture and completion

After Frida startup is verified, the controller launches the dumper as the
second background child, supplying its internal `--non-interactive` flag. The
dumper still checks the exported signature and must successfully hook a supported
layout; Android API level alone cannot establish that the capture is supported. Once both workers
report ready, the dumper's progress check warns after roughly 35 seconds if no
completed, verified pair exists, including time spent in browser startup, but waits
indefinitely while the session remains healthy for user playback or a browser
permission action. The dumper owns the single refresh attempt described in the
[Chrome guide](chrome.md#post-readiness-warning-and-refresh); full auto mirrors
its status event and does not run a separate timer or refresh.

Only the first newly completed, read-back-verified pair from this controller
run counts as its result: `client_id.bin` and `private_key.pem` must both be
closed and verified. Existing files are ignored for completion and are not
reused as this run's result. A failed or incomplete write can be retried by a
later callback. The parent terminal reports the resulting `key_dumps/` folder.

At each full-auto startup, the controller creates or overwrites these four fixed
files under `logs/`:

| Log | Contents |
| --- | --- |
| `logs/init.log` | Complete raw stdout and stderr from the shared initialization and bootstrap process. |
| `logs/frida.log` | Complete raw stdout and stderr from the Frida child process. |
| `logs/dumper.log` | Complete raw stdout and stderr from the dumper child process, including streaming RSA, build, and error output. |
| `logs/full_auto.log` | Complete raw stdout and stderr from the full-auto controller plus captured parent-subprocess diagnostics. |

All four streams are retained without filtering, redaction, or truncation, so
normal RSA, build, and error output remains available for diagnosis. The logs
remain after success, Ctrl+C, or an error until the next full-auto startup
overwrites them or the user purges them. The original terminal remains a live
view of controller progress, errors, results, and log paths; those controller
messages and captured parent-subprocess diagnostics are retained in
`logs/full_auto.log`. Captured subprocess output is routed exclusively to that
log rather than printed into the controller console. The repository's root
`logs/` directory is gitignored. Manual setup and dumper runs keep their
ordinary terminal output.

On successful pair verification, the controller waits three seconds for the
child output to settle, then attempts
`adb -s SELECTED_SERIAL shell am force-stop com.android.chrome` with a
10-second timeout. This closes Chrome without deleting browsing data or the
saved pair, and does not revert earlier Chrome debug-app or command-line flag
changes. If the ADB stop fails, the controller warns and still cleans the
owned child processes and Frida server, retaining the saved pair. Cancellation
or an error before a completed pair still runs the dumper child's own bounded
five-second Chrome exit cleanup after that child has selected a device. Before
the dumper is launched, the full-auto controller performs no Chrome closure.

After that success cleanup, the controller closes only the child processes and
Frida server it started before the parent exits. **Ctrl+C** follows the same
owned cancellation sequence. On Windows, `CTRL_BREAK` is mapped to that
cancellation path. The controller never promises recovery of unrelated
processes or remote Android state. Disposable PID and status metadata lives
under `.tmp/full-auto-*`; normal completion and a handled Ctrl+C remove that
metadata after cleanup, and it never contains key bytes. If owned cleanup
cannot finish, the controller warns and retains the status metadata for
diagnosis.

## Platform scope

Local tests cover POSIX background supervision, and native Windows supervision
is mocked. The latest user logs plus independent file parsing and matching
verified one successful complete pair and cleanup on Android 12 / API 31
x86_64 with Frida 17.18.0 and CDM 16.1.0. That evidence applies to the tested
target only and is not a blanket API or platform compatibility claim. The new
Chrome-stop cleanup paths have not yet been device-tested.
