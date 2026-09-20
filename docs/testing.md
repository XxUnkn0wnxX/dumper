# 🧪 Testing and verified scope

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🧩 Dumper operation](dumper.md) · [🧰 Frida setup](frida-setup.md)

Run these commands from the repository root, where `dump_keys.py` and
`requirements.txt` are located. The tests use Python's built-in `unittest`; no
GitHub Actions setup or separate test-runner package is required.

## Setup

Reuse the project's `.venv` from the [Python setup guide](setup.md). If it does
not exist, create it and install the regular requirements:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade -r requirements.txt
```

The commands below invoke `.venv/bin/python` directly, so activation is optional.
On Windows, use `.venv\Scripts\python.exe` instead.

## Run all tests

```sh
.venv/bin/python -m unittest discover -s tests -v
```

A successful run ends with `OK` and exits with status `0`; a failing run reports
`FAIL` or `ERROR` and exits nonzero. The Python suite includes the JavaScript
detection wrapper. When Node.js is available it runs
`tests/test_cdm_detection.js`; without Node.js that wrapper skips the JavaScript
check.

The checked-in protobuf binding uses the exact runtime version pinned in
`requirements.txt`. Compatibility tests require no compiler; optional
regeneration checks are documented in the [protobuf guide](protobuf.md).

## Run a focused check

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_device_selection.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_device_selection.py' -k explicit_iphone -v
.venv/bin/python -m unittest discover -s tests -p 'test_cdm_cli.py' -v
.venv/bin/python -m unittest discover -s tests -p 'test_protobuf.py' -v
.venv/bin/python -m unittest tests.test_diagnostics tests.test_capture_progress -v
.venv/bin/python -m unittest tests.test_browser tests.test_cdm_cli -v
.venv/bin/python -m unittest tests.test_connection tests.test_cdm_cli -v
.venv/bin/python -m unittest tests.test_cli_common tests.test_frida_cancellation -v
.venv/bin/python -m unittest tests.test_bootstrap tests.test_frida_host_sync -v
.venv/bin/python -m unittest tests.test_init tests.test_bootstrap_entrypoints -v
.venv/bin/python -m unittest tests.test_full_auto tests.test_auto_processes tests.test_auto_session tests.test_auto_logging tests.test_auto_init tests.test_auto_frida -v
.venv-wvd/bin/python -m unittest tests.test_generate_wvd -v
.venv/bin/python -m unittest tests.test_wvd_bootstrap -v
.venv/bin/python -m unittest tests.test_bootstrap_pip_output -v
```

The pip-output checks run a real offline `--dry-run` against the interpreter's
already-installed pip and create/remove a disposable venv under `.tmp/` to
verify rebuild prerequisites. They do not install project packages or access
Android, saved keys, or WVD outputs. Corruption/rebuild tests use temporary
fixtures; public CLI help was also checked with both `-h` and `--help`.

The WVD generator tests run under `.venv-wvd` because they exercise the pinned
`pywidevine` dependency. The bootstrap-boundary tests run under the ordinary
`.venv`; both groups use synthetic inputs and dependency/process mocks and make
no live-device or license-validation claim.

Run the JavaScript harness directly when Node.js is installed:

```sh
node tests/test_cdm_detection.js
```

For the Frida helper's focused tests, see the commands in the
[Frida setup guide](frida-setup.md#maintainer-checks). They are mocked/local
checks and do not require a real device. To include the optional 31-second
foreground lifetime test on macOS or Linux:

```sh
FRIDA_TEST_LONG_SESSION=1 .venv/bin/python -m unittest discover -s tests -p 'test_frida_terminal.py' -v
```

## Additional checks

Compile Python files without running the dumper:

```sh
.venv/bin/python -m compileall -q Helpers init.py full_auto.py dump_keys.py tests tools
```

Check installed dependency versions:

```sh
.venv/bin/python -m pip check
```

## Coverage

The suite uses simulated Frida devices to check:

- Android selection when an iPhone appears first, including misleading device names.
- Rejection of iOS, desktop Linux, and missing or malformed OS metadata.
- Metadata-query failures and cancellation-timer cleanup.
- Selection of an explicit Android device and rejection of an explicit iPhone.
- Errors when multiple Android devices are available or a requested ID is missing.
- Delayed discovery, including Android appearing during another device's OS probe.
- CLI argument forwarding, automatic versus explicit layout selection, invalid choices,
  clean hook failures, session cleanup, and no-hook failure handling.
- Continuing with a working library when another library fails initialization.
- Clean Ctrl+C shutdown during startup or capture wait, including discovery-session
  cleanup without swallowing cancellation.
- Selected-device loss, capture-session detachment, bounded agent health checks,
  explicit disconnect logs, and cleanup without deleting saved output.
- Actionable startup errors for missing Python dependencies, unreachable devices,
  stopped servers, and Frida connection failures without hiding unrelated errors.
- Optional ADB client reporting and separate host/server Frida versions, including
  cancellation, mismatch warnings, and diagnostic-session cleanup.
- Single-URL browser configuration, exact ADB matching, Chrome flag preservation,
  shell quoting, and nonfatal browser failures. Browser tests mock all ADB calls.
- Client-ID CDM version reporting before key matching, retained RSA/build-info output,
  and delayed one-time guidance when RSA captures have not produced a pair.
- Full legacy protobuf schema compatibility, synthetic Protobuf 3.19.3 requests,
  field presence, unknown fields, and certificate/key matching without output files.
- Output names based on actual client-ID CDM metadata and Android API level, portable
  folder names, timestamped collisions preserving earlier pairs, and exactly one
  verified pair per invocation. Successful-save logs include repository-relative paths.
- Frida setup device selection, root checks, installation, cache integrity, network
  failures, exact process identity, foreground terminal I/O, Ctrl+C, bounded shutdown,
  nested root-shell exits, error statuses, and cancellation before upload preserving
  complete cache/installed files while cleaning only an owned partial upload.
- Protobuf regeneration cancellation, temporary staging cleanup, tracked binding and
  requirements rollback, and the explicit non-rollback boundary for pip runtime updates.
- Automatic project environment initialization and reuse, preservation of custom
  active venvs, argument forwarding, partial dependency repair, default bundled
  ADB platform conditions, and cancellation without global pip installs.
- Exact host Frida upgrades/downgrades, selected cache fallback versions, venv and
  pip configuration guards, complete dependency preflight, fresh import checks,
  and failure before Android deployment. Package operations are mocked.
- Full-auto initialization, API/signature gates, per-run completion events, both-file
  verification, warning-only playback delay, owned-process cleanup, persistent raw
  logs, and single-run protection against concurrent log overwrites.

The JavaScript harness executes the actual hook script with simulated Frida APIs.
It checks both verified signatures, all manual labels, rejection of changed or
ambiguous signatures before hooks are installed, exclusion of data exports, and
request-hook attachment failures.

`tests/fixtures/cdm_signatures.json` contains signatures extracted from 12 ELF
libraries across eight Android 9–13 SDK packages, including Android 12L. Each
fixture records its source package/revision, library SHA-256, architecture
pointer size, and first output argument position. Neither SDK images nor library
binaries are needed to run the tests.

No connected device, running Frida server, or ADB connection is required. The
tests do not access real devices; output tests write only synthetic pairs in
temporary directories. Live device claims below remain separate evidence.

## Verified scope

**User-confirmed emulator capture testing: Android 9–13 / API 28–33**, completed on
2026-09-20 using Android Studio emulators only. **No physical phones have been
tested.** The emulator images provided root access; the user did not root any
physical device. Earlier full-auto logs and saved files were also independently
checked on an Android 12 / API 31 x86_64 emulator with
Frida 17.18.0 and CDM 16.1.0: both files formed a matching pair and cleanup
completed. Host-platform and device-specific limits are recorded below.

| Area | Evidence | Still needs verification |
| --- | --- | --- |
| Python | Current development and regression checks run on Python 3.14.0; tested up to Python 3.14. The stated minimum is Python 3.10. | A complete matrix across every supported Python and host OS version. |
| Experimental full auto | Offline controller/logging tests and local POSIX process supervision. Independent log and file parsing/matching verified one complete Android 12 / API 31 x86_64 emulator run with Frida 17.18.0, CDM 16.1.0, and cleanup. | A broader full-auto Android matrix, physical devices, and native Windows lifecycle checks. |
| Manual capture | User-confirmed emulator capture testing through API 33. | Physical devices and additional library builds. |
| Automatic layout detection | User-confirmed emulator capture range is API 28–33. Detailed earlier examples include Android 9 / API 28 with plain `python dump_keys.py`, `libwvhidl.so`, and `args[4]`, plus the verified API 31 full-auto emulator run using `args[5]`. Offline checks cover 12 library fixtures from eight Android 9–13 SDK packages, including Android 12L. | Physical devices, additional library builds, and Android 14+ signatures. |
| Protobuf | Updated binding exercised by the user-confirmed capture workflow through API 33. Schema and serialization regressions also use synthetic requests from the original Protobuf 3.19.3 binding. | Validation after future schema/compiler/runtime updates. |
| Capture folders | Live capture with the current layout, including an independently matched pair in `CDM 16.1.0 - API 31`; synthetic tests cover labels, timestamp collisions, and preservation of existing pairs. | Additional host filesystem behavior and failure scenarios. |
| WVD generation | On macOS with Python 3.14.0 and pywidevine 1.9.0, six saved pairs from API 28–33 converted to Android L3 WVD v2 and passed private-key/client-ID round-trip checks. A rerun replaced the outputs, all source files stayed unchanged, and the main venv package set stayed unchanged. Synthetic tests cover invalid pairs, relative output paths, replacement, and interruption cleanup. | Native Windows/Linux runs and license-service acceptance. |
| Frida setup helper | User-confirmed emulator setup on Android 9, later verified API 31 full-auto emulator setup with Frida 17.18.0, and live API 30 emulator shutdown recovery. Mocked lifecycle/cache tests and local terminal checks cover other paths; an official release download was checked for integrity, extraction, cache reuse, and cleanup. | Physical devices, additional `--shell` and root-manager combinations, and native Windows terminals. |
| Environment initialization and Frida package sync | Mocked venv/pip, dependency repair/failure, platform conditions, version selection, relaunch, and cancellation checks. On macOS, existing-venv initialization passed both inside and outside the venv; a real outside-venv relaunch preserved arguments and working directory without installing packages. | Fresh-environment installation and real package transitions on supported macOS, Linux, and Windows hosts; native Windows relaunch. |

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
Google Play images for API 29–32, and additional `libwvdrmengine.so` copies in
the API 29–32 samples. Fixtures record SDK package revisions, library hashes,
and exact signatures without shipping library binaries.

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
