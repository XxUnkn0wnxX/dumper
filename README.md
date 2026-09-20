# 🧩 Dumper

A Python and Frida tool for capturing Widevine L3 client IDs and matching private
keys from rooted Android devices. This fork includes Android device selection,
automatic request-layout detection, browser test-page setup, and maintainer
tools.

## Android compatibility

Capture testing was user-confirmed on **Android 9–13 / API 28–33** on
2026-09-20, using the tested emulator images.

| Android version | API level | Capture testing | Full auto |
| --- | --- | --- | --- |
| Android 9 | 28 | ✅ User-confirmed | Allowed by the version check |
| Android 10 | 29 | ✅ User-confirmed | Allowed by the version check |
| Android 11 | 30 | ✅ User-confirmed | Allowed by the version check |
| Android 12 | 31 | ✅ User-confirmed | Allowed by the version check |
| Android 12L | 32 | ✅ User-confirmed | Allowed by the version check |
| Android 13 | 33 | ✅ User-confirmed | Allowed by the version check |
| Android 14 and newer | 34+ | 🧪 Unverified; Android 14–17 work is planned | Outside the allowed range |
| Earlier Android versions | Below 28 | Unverified by this fork | Outside the allowed range |

Full auto enforces **API 28–33** and also requires a recognized Widevine
signature. All capture requires root access; the Android version alone does
not establish compatibility with every device or library build. Prefer
**Google APIs** emulator images; see [Android setup](docs/android-setup.md#choose-an-emulator-image).

See [testing and verified scope](docs/testing.md#verified-scope) for the evidence,
[full-auto usage](docs/full-auto.md) for its checks, and
[planned SDK work](docs/TODO.md) for newer Android versions.

## Documentation

| Guide | Scope |
| --- | --- |
| 🧱 [Checkout and Python setup](docs/setup.md) | Install Python/Git with Homebrew, Chocolatey, or a Linux package manager; initialize `.venv` and run the tools. |
| 📱 [Android, ADB, and root setup](docs/android-setup.md) | Android Studio installs for each OS, Platform-Tools/PATH setup, emulator images, root checks, and authorization. |
| 🧰 [Frida server setup](docs/frida-setup.md) | `setup_frida.py` workflow, arguments, cache, foreground operation, cleanup, and cancellation. |
| 🧬 [Protobuf schema and regeneration](docs/protobuf.md) | Regeneration arguments, runtime pinning, schema provenance, and archive references. |
| 📦 [WVD generation](docs/wvd.md) | The strict `.venv-wvd` environment, recursive pair conversion, validation, and output replacement rules. |
| 🧩 [Dumper operation](docs/dumper.md) | Device selection, test-page configuration, capture/output behavior, layout detection, and dumper arguments. |
| 🌐 [Chrome browser setup](docs/chrome.md) | Onboarding suppression, autoplay flags, compatibility, and how to undo testing settings. |
| 🤖 [Experimental full-auto workflow](docs/full-auto.md) | Background initialization, Frida, and dumper orchestration with four persistent raw logs, ownership boundaries, flags, and current platform scope. |
| 🧪 [Testing and verified scope](docs/testing.md) | Regression commands, coverage, live evidence, and current Android limits. |
| 📝 [Planned SDK work](docs/TODO.md) | Android 14–17 module inspection and fixture work. |
| 📦 [Source archives](archives/wks-keys/README.md) | Local WKS-KEYS protobuf snapshots, inventory, and integrity checks. |

## Quick start

New computer? Start with [Python and Git installation](docs/setup.md#install-python-and-git)
and [Android Studio / SDK setup](docs/android-setup.md#install-android-studio).
The [setup guide](docs/setup.md) has complete checkout and environment commands.
For a new checkout on macOS or Linux:

```sh
git clone --branch main git@github.com:XxUnkn0wnxX/dumper.git
cd dumper
python3 init.py
```

If the installation guide selected `python3.14` explicitly, use that in place
of `python3` in these commands.

Install Python 3.10 or newer first. **Tested up to Python 3.14** (current
development and regression checks use Python 3.14.0).
**On initial setup, run `init.py` before the
dumper or tools.** It creates missing or checks existing `.venv` and
`.venv-wvd` environments, repairs incomplete environments when needed, and
exits without device work. Healthy environments are checked without package
mutation. An already active custom main venv is accepted; when `.venv-wvd` is
active, `init.py` selects `.venv` for the main requirements so the two
requirement sets stay separate.

If you skip initialization, the dumper and tools have a shared bootstrap
fallback: outside any venv they prepare and enter `.venv` automatically. That
fallback is for the main requirements only; WVD generation falls back only to
`.venv-wvd`. An already active venv is used as-is. Full details are in the
[setup guide](docs/setup.md).

For the experimental orchestrated workflow, run `python3 full_auto.py` after
`init.py` (`py -3 full_auto.py` in Windows PowerShell); see the
[full-auto guide](docs/full-auto.md) for its device gate and cleanup behavior.

Before starting capture, follow the [Android setup guide](docs/android-setup.md)
to install ADB and prepare a rooted device or root-capable emulator. Prefer a
Google APIs image over a stock Google Play Store image. Connect and authorize
the device, then wait for its unlocked home screen to be fully responsive.
For manual operation, run the Frida setup command from the repository root and
keep its terminal open:

```sh
python3 tools/setup_frida.py
```

The helper aligns its Python Frida package with the Android server before
deployment, including dependency checks. Details are in the
[Frida setup guide](docs/frida-setup.md#host-python-package-synchronization).

In a second macOS/Linux terminal, change back to the repository root and run:

```sh
python3 dump_keys.py
```

<details>
<summary>🪟 Windows PowerShell setup</summary>

For Windows PowerShell, initialize first, then start the helper from the
repository root:

```powershell
py -3 init.py
py -3 tools\setup_frida.py
```

In a second terminal, change to the repository root and run `py -3 dump_keys.py`.
Automatic initialization avoids requiring PowerShell activation. Manual setup
and direct `.venv\Scripts\python.exe` commands are in the
[setup guide](docs/setup.md#manual-environment-setup).

</details>

After hooks are ready, the dumper opens the configured test page automatically
when ADB/Chrome setup is available. Watch for `Key pairs saved at ...`; press
Ctrl+C when finished. Manual playback and browser cleanup details are in the
[dumper guide](docs/dumper.md).

Ctrl+C stops the dumper cleanly and retains saved output. See the
[dumper guide](docs/dumper.md#capture-cancellation-and-terminal-state) and
[Frida cancellation guide](docs/frida-setup.md#cancellation-and-cleanup) for the
current cleanup and platform limits.

## Community references

| Guide or discussion | What it covers |
| --- | --- |
| [Dumping Your own L3 CDM with Android Studio](https://forum.videohelp.com/threads/408031-Dumping-Your-own-L3-CDM-with-Android-Studio) | Illustrated Android Studio/emulator setup and community support. |
| [Decryption and the Temple of Doom](https://forum.videohelp.com/threads/404994-Decryption-and-the-Temple-of-Doom) | Broader CDM and decryption background, guides, and community discussion. |
| [Now out of date: Archived for reference](https://forum.videohelp.com/threads/414908-Now-out-of-date-Archived-for-reference) | Historical reference to the archived version of the original guide. |

## Credits

Thanks to the original dumper authors and contributors, and to
[Frida](https://frida.re/docs/android/) for the instrumentation toolkit.
