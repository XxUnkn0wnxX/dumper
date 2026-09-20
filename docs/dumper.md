# 🧩 Dumper operation

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🤖 Full-auto](full-auto.md) · [🧪 Testing](testing.md)

Run these commands from the repository root. Outside any virtual environment,
shared startup [prepares and enters `.venv`](setup.md#automatic-environment-setup);
an already active custom venv is used as-is. The dumper selects a verified
Android Frida device, detects a supported
`PrepareKeyRequest` layout, installs hooks, and waits for Widevine playback.
Automatic detection recognizes known layouts; it does not identify an exact CDM
version or guarantee that a device can be captured.

## Choose a device

The dumper selects a Frida USB device whose system metadata identifies Android.
It ignores iPhones and other operating systems. If multiple Android devices are
available, list them and select an ID explicitly:

```sh
frida-ls-devices
python dump_keys.py --device-id emulator-5554
```

This is the Frida device ID. The setup helper uses the ADB serial shown by
`adb devices -l`; use the identifier reported by the relevant tool.

If startup cannot find or reach an Android Frida device, the dumper prints an
error with recovery steps and exits nonzero without a traceback. This covers a
stopped or unreachable server, connection failures during the initial process
scan, and missing Python dependencies. Missing dependencies include the
`python -m pip install -r requirements.txt` command; `--help` remains available
without them.

Connect and authorize the device, and keep a root Frida server running with a
version matching the host's `frida` package. To launch an existing server, run
`python tools/setup_frida.py --shell` in another terminal; for a fresh setup,
follow the [Frida setup guide](frida-setup.md). The dumper uses Frida directly,
so an external `adb` executable is optional for capture. Automatic browser launch
and the setup helper require ADB; both prefer the system PATH, then use the
bundled venv fallback installed with the main requirements on supported hosts.

Startup reports the available **ADB client version**, **host Python Frida
version**, and **connected Frida server version**. ADB version discovery uses
PATH first, then the optional venv binary. The server version comes from a
temporary diagnostic session in the connected server, which is detached after
the query. Version probes have short timeouts; unavailable diagnostics are
reported and startup continues, while a confirmed host/server mismatch produces
a warning.

## Automatic test-page launch

[`drm_test_site.txt`](../drm_test_site.txt) contains **one active HTTPS URL**.
Replace that line to change the opened page. The reference file
[`drm_test_sites_reference.txt`](../drm_test_sites_reference.txt) lists
alternatives and testing notes; the dumper never reads it. There is no random
selection, rotation, or automatic fallback.

The active file may contain blank lines and whole-line `#` comments. URL
fragments such as `#build=compiled` are preserved. An empty, unreadable,
invalid, or multiple-URL file produces a warning and skips browser launch. The
default file is located relative to the repository, while a custom `--site-file`
path is relative to the current directory unless it is absolute.

The launcher requires an online ADB device whose serial exactly matches the
selected Frida device ID, and an installed, enabled `com.android.chrome`. It
applies the settings below, then restarts Chrome before opening the URL.
It always runs `am force-stop com.android.chrome` before the new launch. This
closes an already-open Chrome instance and also succeeds when Chrome is stopped.
If that stop fails, the launcher warns and does not open another instance.

| Setting | Purpose and effect |
| --- | --- |
| `am set-debug-app --persistent com.android.chrome` | Selects Chrome as Android's debug app so supported Chrome builds can read testing flags while ADB debugging is enabled. Replaces any previously selected debug app and persists across reboots. Does not enable “Wait for debugger.” |
| `--disable-fre` | Skips Chrome's first-run flow, including welcome/sign-in prompts on supported versions. |
| `--no-first-run` | Suppresses supported first-run initialization behavior. |
| `--autoplay-policy=no-user-gesture-required` | Allows media autoplay without an initial tap; the page still has to request playback. |

The three flags are written to `/data/local/tmp/chrome-command-line` with mode
`0644`. Existing values of these flags are replaced; unrelated flags are
preserved. Desktop-mode and user-agent settings are left unchanged. The
launcher does not change `ro.debuggable`, enable USB debugging, or restart Frida
or ADB. See [Android activity-manager commands](https://developer.android.com/tools/adb#am)
and [Chrome's autoplay testing flag](https://developer.chrome.com/blog/autoplay/#developer-switches).

These settings remain on the device for subsequent launches. The log confirms
that the URL was opened, not that playback or a dump succeeded. The page must
initiate playback itself; allowing autoplay does not press a custom Load/Play
button or solve browser challenges. Missing ADB/Chrome, device mismatches,
timeouts, or launch errors leave the dumper capturing with manual-playback
guidance.

To keep browser setup and navigation entirely manual:

```sh
python dump_keys.py --no-browser
```

`--no-browser` skips only browser configuration and navigation; it does not
disable exit cleanup. If a selected device is available, the dumper still
attempts to stop Chrome, including Chrome opened manually by the user. To use
a different active URL file:

```sh
python dump_keys.py --site-file my_test_site.txt
```

<details>
<summary>↩️ Undo Chrome testing settings on an emulator or real phone</summary>

Stop the dumper first. Use `--no-browser` on future runs if you do not want the
settings reapplied. Replace `emulator-5554` with the phone's ADB serial.

Preserve unrelated Chrome flags by copying the current file to a repository
`.tmp` folder. On macOS/Linux, create it with:

```sh
mkdir -p .tmp
adb -s emulator-5554 pull /data/local/tmp/chrome-command-line .tmp/chrome-command-line
```

In Windows PowerShell, use `New-Item -ItemType Directory -Force .tmp` before
the equivalent `adb` command.

Open `.tmp/chrome-command-line` in a text editor. Remove
`--disable-fre`, `--no-first-run`, and
`--autoplay-policy=no-user-gesture-required`, keeping the first executable
placeholder (`_` or the original name) and any other flags. Restore previous
custom values if applicable, then apply the file and clear the selected debug app:

```sh
adb -s emulator-5554 push .tmp/chrome-command-line /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell chmod 644 /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell am clear-debug-app
adb -s emulator-5554 shell am force-stop com.android.chrome
```

If the file contained only the dumper's three flags and you want to remove it:

```sh
adb -s emulator-5554 shell rm /data/local/tmp/chrome-command-line
```

`am clear-debug-app` clears Android's current debug-app selection; it does not
restore a previously selected app. If another debug app was selected before
testing, reselect it under **Developer options → Select debug app**, including
the previous “Wait for debugger” preference. The dumper does not save the old
debug-app selection or previous values of its managed flags. These steps do not
clear Chrome browsing data or undo first-run choices already saved by Chrome.

</details>

## Chrome cleanup on exit

After an Android device has been selected, the dumper attempts the bounded
command `adb -s SELECTED_SERIAL shell am force-stop com.android.chrome` when it
exits. The single ADB command has a five-second bound and runs on normal
completion, Ctrl+C, Frida-server disconnect, ADB disconnect, and startup
failure or cancellation after device selection. An unreachable device produces
a best-effort warning and cannot be closed; cleanup continues. Help, argument
parsing errors, and failures before a device is selected do not run this
command.

Stopping Chrome does not delete browsing data or saved key files and does not
revert Chrome debug-app or command-line flags. This exit cleanup also runs with
`--no-browser`; that option skips setup and navigation only.

## Capture cancellation and terminal state

The dumper shares terminal handling in [`Helpers/CLI.py`](../Helpers/CLI.py). At
startup it repairs a POSIX terminal left in raw mode by an earlier ADB session,
restoring normal newline handling and `Ctrl+C` signal settings. Redirected
streams and native Windows consoles are left unchanged.

**Ctrl+C** during startup or capture exits with status `0`, keeps any already
saved key files, and leaves the existing RSA/key debug output available. After
hooks are ready, a manual run continues waiting for playback and later
callbacks even after its first pair is saved; press Ctrl+C to finish the run.
The cleanup path protects Frida sessions from a repeated interrupt. A device or
Frida disconnect exits status `1` with saved output retained. Native Windows
terminal behavior and physical-device capture remain subject to the live scope
in the [testing guide](testing.md#verified-scope).

## Output

The dumper writes a pair when a license request's device certificate matches a
previously captured RSA private key:

```text
key_dumps/
└── <android-device>/
    └── private_keys/
        └── CDM <version> - API <level>/
            ├── client_id.bin
            └── private_key.pem
```

For example, an Android 9 capture reporting CDM `14.0.0` is saved under
`key_dumps/Android Emulator 5554/private_keys/CDM 14.0.0 - API 28/`.

| Folder value | Source |
| --- | --- |
| Android device | The selected Frida device's display name, distinct from the ADB serial. |
| CDM version | `widevine_cdm_version` in the captured client ID; `--cdm-version` does not set it. |
| API level | The selected Android device's API level reported by Frida. |

Unavailable metadata is labelled `unknown` and logged; version values are never
guessed from a layout signature. Folder components are sanitized for Windows,
macOS, and Linux, so the separator is `-` instead of the Windows-invalid `|`.

If the destination already exists, the new pair goes into a sibling folder with
the computer's local date and time, for example
`CDM 14.0.0 - API 28 (2026-09-20 15-45-30)`. Same-time collisions receive a more
precise timestamp. Existing pairs are preserved. Each dumper invocation saves
at most one newly verified pair: later matching callbacks reuse/report that
invocation's saved folder and do not create another directory. A failed or
incomplete write does not count as success and may be retried. Success is
recorded only after both files are closed and their contents have been read
back and verified.

After both files are saved and verified, the log prints the exact directory
relative to the repository root:

```text
Key pairs saved at key_dumps/Android Emulator 5554/private_keys/CDM 14.0.0 - API 28
```

Existing RSA/key output and debug verbosity remain visible. Hook setup or an
unmatched request alone does not create a pair. As soon as a license request is
parsed, the dumper prints the client ID's `widevine_cdm_version` at INFO level,
once per distinct reported version. If RSA keys arrive but no pair is saved
after 15 seconds, a one-time warning suggests triggering playback and checking
supported layout options. Missing output alone does not prove a version mismatch.

Older output is left in place: its two numeric folder names were the
certificate's **Widevine system ID** and the **first ten decimal digits of the
RSA key modulus**, respectively.

## Layout detection and options

`--cdm-version auto` is the default. The Frida agent checks the complete
exported C++ `PrepareKeyRequest` signature before attaching hooks and selects its
known output argument layout. Android and Frida version numbers do not drive
this selection.

An unknown, missing, or ambiguous signature stops setup for that library. Other
matching libraries are still tried; startup fails if no library can be hooked.
The default module list is `libwvaidl.so` and `libwvhidl.so`. Without an
explicit function name, the agent scans lowercase function exports.

Run `python dump_keys.py` with the arguments below. With no arguments it selects
an Android device automatically, uses automatic layout detection, and attempts
to open the configured test page after hooks are ready.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| `-h`, `--help` | Show command-line help and exit. | — | `python dump_keys.py --help` |
| `--cdm-version LABEL` | Select automatic detection or a known manual request layout; see the labels below. | `auto` | `python dump_keys.py --cdm-version auto` |
| `--device-id ID` | Select an Android Frida USB device explicitly. | Select the only available Android device. | `python dump_keys.py --device-id emulator-5554` |
| `--function-name NAME` | Hook a specific private-key function export for the target build. | Scan lowercase function exports. | `python dump_keys.py --function-name zrtoooke` |
| `--module-name NAME [NAME ...]` | Search one or more named Widevine libraries. | `libwvaidl.so libwvhidl.so` | `python dump_keys.py --module-name libwvhidl.so libwvaidl.so` |
| `--no-browser` | Skip browser configuration and navigation during startup. Exit cleanup still attempts the selected-device Chrome stop. | Browser launch enabled. | `python dump_keys.py --no-browser` |
| `--site-file PATH` | Read the single active HTTPS test-page URL from a different text file. | Repository `drm_test_site.txt` | `python dump_keys.py --site-file my_test_site.txt` |
| `--non-interactive` | Internal flag reserved for `full_auto.py`, which supplies it automatically. Requires `--cdm-version auto` and no `--function-name`. Omit it for manual runs. | Off | Set by `python full_auto.py` |

The full-auto controller supplies `--non-interactive` automatically. Manual
`--cdm-version` and `--function-name` remain available for advanced direct
dumper runs and are outside that workflow's coverage.

<details>
<summary>🔎 Manual layouts and library overrides</summary>

Use a manual label only after verifying the layout for that library. These labels
select argument positions; they do not establish the installed CDM, Android, or
Frida version.

| Manual label | First request-output argument |
| --- | --- |
| `14.0.0`, `15.0.0`, `16.0.0` | `args[4]` |
| `16.1.0`, `17.0.0` | `args[5]` |

```sh
python dump_keys.py --cdm-version 17.0.0
python dump_keys.py --cdm-version 17.0.0 --function-name zrtoooke
python dump_keys.py --module-name libwvhidl.so libwvaidl.so
```

Function names depend on the library build. `zrtoooke` is a known candidate in
the tested Android 13 library. Library names also vary; inspect the device's
`/vendor/lib/` and `/vendor/lib64/` directories before overriding them. The
runtime signature table and maintainer comments live in
[`Helpers/script.js`](../Helpers/script.js); captured sample signatures live in
the [test fixtures](../tests/fixtures/cdm_signatures.json).

</details>
