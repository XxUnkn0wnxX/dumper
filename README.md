# 🧩 Dumper

> [!WARNING]
> **Experimental branch — active rework**
>
> This branch is experimental and is currently being reworked. Features and
> behavior may change, and live device testing is still in progress.

A Python and Frida tool for capturing Widevine L3 client IDs and matching private
keys from rooted Android devices. This fork includes Android device selection,
automatic request-layout detection, browser test-page setup, and maintainer
tools.

## Documentation

| Guide | Scope |
| --- | --- |
| 🧱 [Checkout and Python setup](docs/setup.md) | Automatic `.venv` initialization, custom environments, manual setup, and commands on macOS, Linux, and Windows. |
| 📱 [Android, ADB, and root setup](docs/android-setup.md) | Platform-Tools, emulator images, root checks, authorization, and the bundled ADB fallback. |
| 🧰 [Frida server setup](docs/frida-setup.md) | `setup_frida.py` workflow, arguments, cache, foreground operation, cleanup, and cancellation. |
| 🧬 [Protobuf schema and regeneration](docs/protobuf.md) | Regeneration arguments, runtime pinning, schema provenance, and archive references. |
| 📦 [Optional WVD tooling](docs/wvd.md) | The separate `.venv-wvd` environment and `pywidevine` requirements. |
| 🧩 [Dumper operation](docs/dumper.md) | Device selection, browser flags and undo, capture/output behavior, layout detection, and dumper arguments. |
| 🧪 [Testing and verified scope](docs/testing.md) | Regression commands, coverage, live evidence, and current Android limits. |
| 📝 [Planned SDK and helper work](docs/TODO.md) | Android 14–17 module inspection and the deferred WVD helper. |
| 📦 [Source archives](archives/wks-keys/README.md) | Local WKS-KEYS protobuf snapshots, inventory, and integrity checks. |

## Quick start

The [setup guide](docs/setup.md) has complete checkout and environment commands.
For a new checkout on macOS or Linux:

```sh
git clone --branch develop https://github.com/XxUnkn0wnxX/dumper.git
cd dumper
python3 init.py
```

Install Python 3.10 or newer first. **On initial setup, run `init.py` before the
dumper or tools.** It creates or checks `.venv`, installs the requirements when
needed, and exits without device work. It uses an already active custom venv
instead when one is present.

If you skip initialization, the dumper and tools have a shared bootstrap
fallback: outside any venv they prepare and enter `.venv` automatically. An
already active venv is used as-is; run `init.py` there to prepare or check its
requirements. Full details are in the [setup guide](docs/setup.md).

Before starting either script, follow the [Android setup guide](docs/android-setup.md)
to install ADB and prepare a rooted device or root-capable emulator. Prefer a
Google APIs image over a stock Google Play Store image. Connect and authorize
the device, then wait for its unlocked home screen to be fully responsive.
Run the Frida setup command from the repository root and keep its terminal open:

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
