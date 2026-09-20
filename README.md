# 🧩 Dumper

> [!WARNING]
> **Experimental branch — active rework**
>
> This branch is experimental and is currently being reworked. Features and
> behavior may change, and live device testing is still in progress.

A Python and Frida tool for capturing Widevine L3 client IDs and matching private
keys from rooted Android devices. This fork includes Android device selection,
automatic request-layout detection, and optional maintainer tools.

## Documentation

| Guide | What you will find |
| --- | --- |
| 🧰 [Tools](tools/README.md) | Frida server setup, shell access, ADB installation, and protobuf regeneration. |
| 🧬 [Helpers and schema](Helpers/README.md) | The shipped Protobuf schema, generated binding, and source provenance. |
| 📦 [Source archives](archives/wks-keys/README.md) | Local WKS-KEYS protobuf snapshots, inventory, and integrity checks. |
| 🧪 [Local tests](tests.md) | Environment setup, regression commands, coverage, and live-test limits. |
| 📚 [VideoHelp guides and references](#videohelp-guides-and-references) | Community setup walkthroughs, discussion, and historical references. |

> **Compatibility:** automatic detection recognizes known `PrepareKeyRequest`
> argument layouts. It does not identify an exact CDM version or guarantee that
> a device can be captured. See [verified scope](#verified-scope) for the available
> evidence and remaining live tests.

## Requirements

| Component | Requirement |
| --- | --- |
| Android | A rooted device or root-capable emulator with USB debugging enabled. |
| Python | [Python 3.10 or newer](https://www.python.org/downloads/) on the computer. |
| ADB | Android SDK Platform-Tools, or the optional bundled fallback in [tools/requirements-adb.txt](tools/requirements-adb.txt); see the [installation guide](tools/README.md#install-adb-on-the-computer). |
| Frida | A running Android `frida-server` with root access and a version matching the host's Python `frida` package. |
| Request layout | A recognized exported signature, or a verified manual layout override for the target library. |

> **Emulator image:** in Android Studio, prefer **Services → Google APIs** for
> dumper testing. Stock **Google Play Store** images typically lack `su` and block
> `adb root`. Choose a root-capable debug image; `su` is unnecessary when
> `adb root` works. See [image selection and root checks](tools/README.md#choose-an-emulator-image).

Create the virtual environment and install [requirements.txt](requirements.txt)
from the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade -r requirements.txt
```

<details>
<summary>🪟 Windows PowerShell setup</summary>

Use the environment's interpreter directly; activation is optional:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade -r requirements.txt
```

Replace `python3` in the run commands below with `.venv\Scripts\python.exe`,
and use `.venv\Scripts\frida-ls-devices.exe` for the device-listing command.

</details>

`frida`, `frida-tools`, and `pycryptodome` are unpinned, so `--upgrade` asks pip for
the latest compatible releases. `frida-tools` supplies the Frida command-line
tools. Keep the host and server versions matched when updating.

Protobuf is pinned to the runtime supported by the shipped
[generated binding](Helpers/wv_proto2_pb2.py). Normal installation uses that file
directly. Maintainers can optionally rebuild it using the checked-in schema;
see [protobuf regeneration](tools/README.md#protobuf-regeneration).

Optional `pywidevine` tooling has its own [requirements-wvd.txt](requirements-wvd.txt)
and needs a **separate `.venv-wvd` environment** because its Protobuf requirements
conflict with the dumper's. See [optional WVD tooling](tools/README.md#optional-wvd-tooling)
for setup; automatic WVD creation is not implemented yet.

## Quick start

Run these commands from the repository root with the virtual environment active.

1. Connect the Android device, enable USB debugging, and accept its authorization
   prompt.
2. Prepare and start Frida server using the
   [Frida setup guide](tools/README.md#frida-server-setup). The helper installs and
   starts the server automatically in the foreground of a root terminal session.
   Keep that terminal open while capturing. Use `--shell` to start an existing
   installation without downloading it again.
3. In another host terminal, activate the environment and start the dumper:

   ```sh
   source .venv/bin/activate
   python3 dump_keys.py
   ```

4. After successful hook setup, the dumper opens the URL in
   [drm_test_site.txt](drm_test_site.txt) in Chrome on the selected Android device.
   The default is the DASH-IF Widevine sample. Chrome is configured to skip its
   first-run screens and allow autoplay. If automatic launch is unavailable,
   open the page manually; capture stays running.
5. Watch for `Key pairs saved at ...`. Stop the dumper with **Ctrl+C** when finished;
   it stays running after saving a pair. Cancellation prints `Stopped by user.`
   and exits cleanly without a traceback, including during startup.

> **Need help setting up Android Studio?** See the illustrated walkthrough and
> community discussions under [VideoHelp guides and references](#videohelp-guides-and-references).

### Choose a device

The dumper selects a Frida USB device whose system metadata identifies Android.
It ignores iPhones and other operating systems. If multiple Android devices are
available, list them and select an ID explicitly:

```sh
frida-ls-devices
python3 dump_keys.py --device-id emulator-5554
```

This is the Frida device ID. The setup helper uses the ADB serial shown by
`adb devices -l`; use the identifier reported by the relevant tool.

If startup cannot find or reach an Android Frida device, the dumper prints an
error with recovery steps and exits with a nonzero status, without a traceback.
This also covers a stopped/unreachable server, connection failures during the
initial process scan, and missing Python dependencies. Missing dependencies
include the `python -m pip install -r requirements.txt` command in the error;
`--help` remains available without them.

Connect and authorize the device, and keep a root Frida server running with a
version matching the host's `frida` package. To launch an existing server, run
`python tools/setup_frida.py --shell` in another terminal; for a fresh setup,
follow the [Frida setup guide](tools/README.md#frida-server-setup). The dumper
uses Frida directly, so an external `adb` executable is optional for capture.
Automatic browser launch and the setup helper require ADB; both use the existing
PATH-first, optional-venv fallback.

Startup reports the available **ADB client version**, **host Python Frida
version**, and **connected Frida server version**. ADB version discovery uses
PATH first, then the optional venv binary. The server version comes from a
temporary diagnostic session in the connected server, which is detached after
the query. It is reported separately from the host package version. Version
probes have short timeouts; unavailable diagnostics are reported and startup
continues, while a confirmed host/server version mismatch produces a warning.

### 🌐 Automatic test-page launch

[drm_test_site.txt](drm_test_site.txt) contains **one active HTTPS URL**. Replace
that line to change the opened page. [drm_test_sites_reference.txt](drm_test_sites_reference.txt)
lists alternative pages and their testing notes; the dumper never reads that
reference file. There is no random selection, rotation, or automatic fallback.

The active file may contain blank lines and whole-line `#` comments. URL
fragments such as `#build=compiled` are preserved. An empty, unreadable, invalid,
or multiple-URL file produces a warning and skips browser launch. The default
file is located relative to the repository, while a custom `--site-file` path is
relative to your current directory unless you supply an absolute path.

The launcher requires an online ADB device whose serial exactly matches the
selected Frida device ID, and an installed, enabled `com.android.chrome`. It
applies the settings below, then restarts Chrome before opening the URL.

| Setting | Purpose and effect |
| --- | --- |
| `am set-debug-app --persistent com.android.chrome` | Selects Chrome as Android's debug app so supported Chrome builds can read the testing flags while ADB debugging is enabled. Replaces any previously selected debug app and persists across reboots. Does **not** enable “Wait for debugger.” |
| `--disable-fre` | Skips Chrome's first-run flow, including welcome/sign-in prompts on supported versions. |
| `--no-first-run` | Suppresses supported first-run initialization behavior. |
| `--autoplay-policy=no-user-gesture-required` | Allows media autoplay without an initial tap; the page still has to request playback. |

The three flags are written to `/data/local/tmp/chrome-command-line` with mode
`0644`. Existing values of these flags are replaced; unrelated flags are
preserved. Desktop-mode and user-agent settings are left as they are. The
launcher does not change `ro.debuggable`, enable USB debugging, or restart Frida
or ADB. See [Android's activity-manager commands](https://developer.android.com/tools/adb#am)
and [Chrome's autoplay testing flag](https://developer.chrome.com/blog/autoplay/#developer-switches).

These Chrome testing settings remain on the device for subsequent launches.
The log confirms that the URL was opened, not that playback or a dump succeeded.
The page must initiate playback itself; allowing autoplay does not press a
page's custom Load/Play button or solve browser challenges. Missing ADB/Chrome,
device mismatches, timeouts, or launch errors leave the dumper capturing with
manual-playback guidance.

To keep browser setup and navigation entirely manual:

```sh
python3 dump_keys.py --no-browser
```

`--no-browser` leaves the device's existing Chrome settings as they are. To use a
different active URL file:

```sh
python3 dump_keys.py --site-file my_test_site.txt
```

<details>
<summary>↩️ Undo Chrome testing settings on an emulator or real phone</summary>

Stop the dumper first. Use `--no-browser` on future runs if you do not want these
settings reapplied. Replace `emulator-5554` below with your phone's serial from
`adb devices`.

**Preserve any unrelated Chrome flags:** create a `.tmp` folder in the repository
root if needed, then copy the current flags file to your computer:

```sh
adb -s emulator-5554 pull /data/local/tmp/chrome-command-line .tmp/chrome-command-line
```

Open `.tmp/chrome-command-line` in a text editor. Remove `--disable-fre`,
`--no-first-run`, and `--autoplay-policy=no-user-gesture-required`, keeping the
first executable placeholder (`_` or the original name) and any other flags.
If these settings had custom values before testing, restore those values instead.
Save the file, then apply it and clear the selected debug app:

```sh
adb -s emulator-5554 push .tmp/chrome-command-line /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell chmod 644 /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell am clear-debug-app
adb -s emulator-5554 shell am force-stop com.android.chrome
```

Reopen Chrome normally. If the file contained only the dumper's three flags and
you want to remove the now-unused file, you can also run:

```sh
adb -s emulator-5554 shell rm /data/local/tmp/chrome-command-line
```

`am clear-debug-app` clears Android's current debug-app selection; it does not
restore a previously selected app. If you used another debug app before testing,
reselect it under **Developer options → Select debug app**, including your
previous “Wait for debugger” preference if applicable. The dumper does not save
the previous debug-app selection or the old values of its three managed flags.

These steps remove the testing overrides without clearing Chrome's browsing
data. They do not undo any first-run choices already saved by Chrome.

</details>

### Output

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
| Android device | The selected Frida device's display name, such as `Android Emulator 5554`. This is distinct from the ADB serial `emulator-5554`. |
| CDM version | `widevine_cdm_version` in the captured client ID. The `--cdm-version` layout option does not set this value. |
| API level | The selected Android device's API level reported by Frida, such as `28` for Android 9. |

Unavailable metadata is labelled `unknown` and logged; version values are never
guessed from a layout signature. Folder components are sanitized for Windows,
macOS, and Linux, so the separator is `-` instead of the Windows-invalid `|`.

If the destination already exists, the new pair goes into a sibling folder with
the computer's local date and time, for example
`CDM 14.0.0 - API 28 (2026-09-20 15-45-30)`. Same-time collisions receive a more
precise timestamp. Existing pairs are preserved, including when a later run
captures the same pair. Repeated identical callbacks within one dumper run reuse
that run's saved folder.

After both files are saved and verified, the log prints the exact directory
relative to the repository root, including any timestamp suffix:

```text
Key pairs saved at key_dumps/Android Emulator 5554/private_keys/CDM 14.0.0 - API 28
```

The existing RSA/key output and debug verbosity remain visible alongside this
message. Hook setup or an unmatched request alone does not create a pair.
As soon as a license request is parsed, the dumper also prints the client ID's
`widevine_cdm_version` at INFO level, once per distinct reported version:

```text
Client ID reports widevine_cdm_version: 14.0.0
```

This metadata can appear before a matching private key is available or any files
are saved. It requires a readable captured request, so it cannot choose the
initial hook layout. Automatic hook selection still uses known signatures;
`--cdm-version` selects a supported layout override. Missing or conflicting
client metadata is reported rather than guessed.

If RSA keys arrive but no pair is saved after 15 seconds, a one-time warning
suggests triggering a new Widevine playback/license request and checking the
supported `--cdm-version` layout options. Missing output alone does not prove a
version mismatch. The warning is suppressed after a verified save, and a known
matched pair that fails to save keeps its specific file-error message instead.

Older output is left in place: its two numeric folder names
were the certificate's **Widevine system ID** and the **first ten decimal digits
of the RSA key modulus**, respectively.

## Layout detection and options

`--cdm-version auto` is the default. The Frida agent checks the complete exported
C++ `PrepareKeyRequest` signature before attaching hooks and selects its known
output argument layout. Android and Frida version numbers do not drive this
selection.

An unknown, missing, or ambiguous signature stops setup for that library. Other
matching libraries are still tried; startup fails if no library can be hooked.
The default module list is `libwvaidl.so` and `libwvhidl.so`. Without an explicit
function name, the agent scans function exports whose names contain only
lowercase letters.

Run `python3 dump_keys.py` with the arguments below. With no arguments it selects
an Android device automatically, uses automatic layout detection, and attempts
to open the configured test page after the hooks are ready.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| `-h`, `--help` | Show command-line help and exit. | — | `python3 dump_keys.py --help` |
| `--cdm-version LABEL` | Select automatic detection or a known manual request layout; see the labels below. | `auto` | `python3 dump_keys.py --cdm-version auto` |
| `--device-id ID` | Select an Android Frida USB device explicitly. | Select the only available Android device. | `python3 dump_keys.py --device-id emulator-5554` |
| `--function-name NAME` | Hook a specific private-key function export for the target build. | Scan lowercase function exports. | `python3 dump_keys.py --function-name zrtoooke` |
| `--module-name NAME [NAME ...]` | Search one or more named Widevine libraries. | `libwvaidl.so libwvhidl.so` | `python3 dump_keys.py --module-name libwvhidl.so libwvaidl.so` |
| `--no-browser` | Capture without configuring or opening Chrome through ADB. | Browser launch enabled. | `python3 dump_keys.py --no-browser` |
| `--site-file PATH` | Read the single active HTTPS test-page URL from a different text file. | Repository `drm_test_site.txt` | `python3 dump_keys.py --site-file my_test_site.txt` |

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
python3 dump_keys.py --cdm-version 17.0.0
```

Function names depend on the library build. `zrtoooke` is a known candidate in
the tested Android 13 library, so an explicit selection for that build looks like:

```sh
python3 dump_keys.py --cdm-version 17.0.0 --function-name zrtoooke
```

Library names also vary. Inspect the device's `/vendor/lib/` and `/vendor/lib64/`
directories, then supply the names that apply to your build. Pass multiple names
after one `--module-name` option:

```sh
python3 dump_keys.py --module-name libwvhidl.so libwvaidl.so
```

The runtime signature table and maintainer comments live in
[Helpers/script.js](Helpers/script.js); the captured sample signatures live in
[the test fixtures](tests/fixtures/cdm_signatures.json).

</details>

## Verified scope

| Area | Evidence | Still needs verification |
| --- | --- | --- |
| Manual capture | Reported success on a rooted Pixel 6 Pro running Android 13 with manual layout `17.0.0`. | Other devices and library builds. |
| Automatic layout detection | User-confirmed live success on Android 9 / API 28 with plain `python dump_keys.py` (2026-09-20): Android selection, `libwvhidl.so` detection, automatic `args[4]` layout, and key retrieval. Offline checks also cover 12 library fixtures from eight Android 9–13 SDK packages, including Android 12L. | Live automatic capture on other Android versions and library builds. |
| Protobuf | Schema and serialization regressions using synthetic requests from the original Protobuf 3.19.3 binding; the updated dumper was reported working on Android 9. | Further device coverage and validation after future compiler/runtime updates. |
| Capture folders | Synthetic output tests for CDM/API labels, timestamp collisions, and preservation of existing pairs. | Live capture using the new folder layout. |
| Frida setup helper | User-confirmed Android 9 setup with the earlier manual-start workflow (2026-09-20), mocked lifecycle/cache tests, local terminal checks for Ctrl+C and foreground lifetime, and an official release download with checksum, extraction, cache reuse, and cleanup checks. | Live verification of the corrected foreground startup/replacement flow, launch through `--shell`, and root-manager behavior on other devices. |

**Android 14 and later are outside this fork's current verified scope.** An SDK
fixture proves how that sample's signature is classified; it does not establish
compatibility with every device on the same Android release.

<details>
<summary>📋 Android SDK signature samples</summary>

| Android release | API | Library architecture | Detected output argument |
| --- | --- | --- | --- |
| Android 9 | 28 | x86, 32-bit | `args[4]` |
| Android 10 | 29 | x86, 32-bit | `args[4]` |
| Android 11 | 30 | x86, 32-bit | `args[4]` |
| Android 12 | 31 | x86_64, 64-bit | `args[5]` |
| Android 12L | 32 | x86_64, 64-bit | `args[5]` |
| Android 13 | 33 | x86_64, 64-bit | `args[5]` |

The samples include Google APIs and Google Play variants for API 28 and 33,
Google Play images for API 29–32, and additional `libwvdrmengine.so` copies
present in the API 29–32 samples. Fixtures record SDK package revisions, library
hashes, and exact signatures without shipping the library binaries.

</details>

<details>
<summary>📎 Historical device-specific DRM workaround</summary>

Earlier instructions linked to
[liboemcrypto-disabler](https://github.com/umylive/liboemcrypto-disabler), a Magisk
module whose upstream documentation describes masking `liboemcrypto.so` to work
around DRM playback problems on rooted devices. This is a device-specific
reference, not a general setup requirement. Compatibility with current devices
has not been verified by this fork.

</details>

## VideoHelp guides and references

These community resources provide additional setup help and background. Use this
README and the [tools guide](tools/README.md) for this fork's current commands and
arguments.

| Guide or discussion | What it covers |
| --- | --- |
| [Dumping Your own L3 CDM with Android Studio](https://forum.videohelp.com/threads/408031-Dumping-Your-own-L3-CDM-with-Android-Studio) | Illustrated Android Studio/emulator setup and community support. |
| [Decryption and the Temple of Doom](https://forum.videohelp.com/threads/404994-Decryption-and-the-Temple-of-Doom) | Broader CDM and decryption background, guides, and community discussion. |
| [Now out of date: Archived for reference](https://forum.videohelp.com/threads/414908-Now-out-of-date-Archived-for-reference) | **Historical reference:** the archived, out-of-date version of the original Temple of Doom guide. |

## Tests and maintenance

Run the local regression suite from the repository root:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

The tests use simulated devices and synthetic data. Node.js enables the included
JavaScript harness; that check is skipped when Node.js is unavailable. See the
[test guide](tests.md) for focused checks and coverage, and the
[tools guide](tools/README.md) for helper-specific maintenance and live checks.

## Credits

Thanks to the original dumper authors and contributors, and to
[Frida](https://frida.re/docs/android/) for the instrumentation toolkit.
