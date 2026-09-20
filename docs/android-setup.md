# 📱 Android, ADB, and root setup

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🧰 Frida setup](frida-setup.md)

The dumper and Frida setup helper require an online Android target. The target
must be rooted, or use an emulator image where `adb root` works. The helper does
not root an unrooted device. Wait until Android has finished booting and its
unlocked home screen is visible and responsive before using either script; ADB
can report `device` while Android services are still starting.

## Choose an emulator image

For Android Studio emulator testing across API 28–33, prefer **Services → Google
APIs** when selecting the system image. Root availability depends on the image's
build configuration, not just its Android/API version.

| Image choice | Root access for dumper testing |
| --- | --- |
| **Google APIs** | Preferred: select a root-capable `userdebug` or `eng` build and verify `adb root` after boot. A standalone `su` binary is not required. |
| **Google Play Store** | Stock production images typically have no `su` and disallow `adb root`; they require separate rooting work before the helper can install the server. |

Android documents the [root restriction on Play Store images](https://developer.android.com/studio/run/managing-avds#system-images).
For the debug-root route, look for `ro.debuggable=1` and a `userdebug` or `eng`
build. These properties belong to the image; they are not an AVD checkbox. The
decisive check is a working root shell, as described in
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

The Frida helper tries `adb root` if existing root and `su` are unavailable. On a
physical device, arrange working root access through `su` before using it.

</details>

## Install ADB on the computer

Install Android SDK Platform-Tools globally or place its `platform-tools`
directory on your system `PATH`, so `adb version` works in a new terminal.
Android Studio's SDK Manager can also install Platform-Tools.

| System | Installation |
| --- | --- |
| Windows | Download **SDK Platform-Tools for Windows** from [Android's official downloads](https://developer.android.com/tools/releases/platform-tools#downloads), extract it, and add the directory containing `adb.exe` to `PATH`. Physical devices may also need a manufacturer's [USB driver](https://developer.android.com/studio/run/oem-usb). |
| macOS | Install the [Homebrew android-platform-tools cask](https://formulae.brew.sh/cask/android-platform-tools) with `brew install --cask android-platform-tools`, or use **SDK Platform-Tools for Mac** from [Android's downloads](https://developer.android.com/tools/releases/platform-tools#downloads). |
| Linux | Download **SDK Platform-Tools for Linux** from [Android's downloads](https://developer.android.com/tools/releases/platform-tools#downloads) and add the extracted directory to `PATH`, or install your distribution's ADB package. For USB permissions, follow Android's [Linux device setup](https://developer.android.com/studio/run/device#setting-up). |

Check installation and authorization:

```sh
adb version
adb devices -l
```

Enable USB debugging on a physical device and accept its authorization prompt.
An online ADB entry looks like:

```text
List of devices attached
emulator-5554  device
```

Only entries whose state is exactly `device` are eligible. Entries marked
`offline`, `unauthorized`, or another state are skipped. With multiple online
devices, select one explicitly using `--device-id`.

## ADB resolution

Run `init.py` first as described in the [Python setup guide](setup.md). It
installs the root requirements, including `adbutils==2.12.0` with
`--only-binary=adbutils`, so the supported packaged ADB fallback is prepared by
default. No separate ADB requirements file or manual pip command is needed.
On supported Intel/AMD hosts it is installed even if system ADB is already on
`PATH`; having that fallback available does not change the selection order.

The setup helper resolves ADB in this order:

1. An explicit `--adb PATH` or executable name wins when supplied. An explicit
   path that is missing or not executable fails rather than falling back.
2. Without `--adb`, an `adb` executable found on the host `PATH` is always
   preferred. Global Android SDK Platform-Tools remain the recommended install
   because they also provide the rest of the Android tooling.
3. If PATH has no usable `adb`, the helper locates the packaged binary owned by
   the installed `adbutils` distribution (`adb.exe` on Windows).

The `adbutils==2.12.0` wheel includes the ADB executable and its companion files;
other Android SDK tools are still installed separately. Its
[published wheels](https://pypi.org/project/adbutils/2.12.0/#files) cover Windows
x86/x64, Linux x86_64, and Intel macOS. There is no native ARM-host wheel for this
pinned version. A platform condition in the main requirements skips that package
on ARM hosts so initialization still succeeds; install system Android SDK
Platform-Tools there. The helper inspects the package data directly and does not
create a standalone `adb` shell command; startup prints the selected executable
path. If neither PATH nor the packaged fallback is available, setup stops before
device lookup with an actionable requirements/environment error.

## ARM hosts

On an ARM computer, `init.py` and the bootstrap fallback still create or reuse
the venv and install **all other Python requirements**. Only the bundled
`adbutils` wheel is skipped. If `adb` is also missing from `PATH`, initialization
prints a reminder to install it manually; otherwise there is no manual-install
warning. Neither case prevents the rest of Python setup from completing.
This concerns the **computer's architecture**, not the connected Android
device: an Intel computer can still set up an ARM Android device.

Use the [system installation instructions](#install-adb-on-the-computer) above:
Homebrew/Android SDK Platform-Tools on macOS, a compatible Platform-Tools build
on Windows, or your distribution's native ADB package on Linux. If you need
to compile on Linux, the community
[android-tools build instructions](https://github.com/nmeum/android-tools#installation)
document its CMake-based source build and prerequisites. This is a manual
alternative; the dumper does not compile or install system tools for you.

Put the directory containing your installed or compiled `adb` on `PATH`, open
a fresh terminal, and verify `adb version` and `adb devices -l`. An explicit
`--adb /path/to/adb` is also available to the Frida setup helper. The docs link
to upstream build guidance; native ARM builds have not been validated by this
fork.
