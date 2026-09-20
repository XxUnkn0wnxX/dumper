# 🧩 Dumper

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
| ADB | Android SDK Platform-Tools; see the [installation guide](tools/README.md#install-adb-on-the-computer). |
| Frida | A running Android `frida-server` with root access and a version matching the host's Python `frida` package. |
| Request layout | A recognized exported signature, or a verified manual layout override for the target library. |

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

## Quick start

Run these commands from the repository root with the virtual environment active.

1. Connect the Android device, enable USB debugging, and accept its authorization
   prompt.
2. Prepare and start Frida server using the
   [Frida setup guide](tools/README.md#frida-server-setup). The helper installs the
   server and opens a shell; you start the server yourself.
3. In another host terminal, activate the environment and start the dumper:

   ```sh
   source .venv/bin/activate
   python3 dump_keys.py
   ```

4. Wait for the log to report successful hook setup, then start playback on the
   Android device using the [Bitmovin DRM demo](https://bitmovin.com/demos/drm) or
   [DASH-IF Widevine demo](https://reference.dashif.org/dash.js/v4_latest/samples/drm/widevine.html).
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

### Output

The dumper writes a pair when a license request's device certificate matches a
previously captured RSA private key:

```text
key_dumps/
└── <device>/private_keys/<system-id>/<key-prefix>/
    ├── client_id.bin
    └── private_key.pem
```

`<system-id>` comes from the client ID, and `<key-prefix>` is the first ten decimal
digits of the RSA key modulus. The log reports the save directory. Hook setup or
an unmatched request alone does not create the pair.

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
an Android device automatically and uses automatic layout detection.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| `-h`, `--help` | Show command-line help and exit. | — | `python3 dump_keys.py --help` |
| `--cdm-version LABEL` | Select automatic detection or a known manual request layout; see the labels below. | `auto` | `python3 dump_keys.py --cdm-version auto` |
| `--device-id ID` | Select an Android Frida USB device explicitly. | Select the only available Android device. | `python3 dump_keys.py --device-id emulator-5554` |
| `--function-name NAME` | Hook a specific private-key function export for the target build. | Scan lowercase function exports. | `python3 dump_keys.py --function-name zrtoooke` |
| `--module-name NAME [NAME ...]` | Search one or more named Widevine libraries. | `libwvaidl.so libwvhidl.so` | `python3 dump_keys.py --module-name libwvhidl.so libwvaidl.so` |

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
| Automatic layout detection | Offline checks against the saved device library and 12 library fixtures from eight Android 9–13 SDK packages, including Android 12L. | Live automatic detection and capture. |
| Protobuf | Schema and serialization regressions using synthetic requests from the original Protobuf 3.19.3 binding. | Live device operation after the runtime migration. |
| Frida setup helper | Mocked device/installation tests and an official release download with checksum, extraction, architecture, and cleanup checks. | Device installation, root-manager behavior, and interactive shell access. |

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
