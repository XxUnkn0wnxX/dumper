# 📱 Android, ADB, and root setup

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🧰 Frida setup](frida-setup.md)

The dumper and Frida setup helper require an online Android target. The target
must be rooted, or use an emulator image where `adb root` works. The helper does
not root an unrooted device. Wait until Android has finished booting and its
unlocked home screen is visible and responsive before using either script; ADB
can report `device` while Android services are still starting.

For the main illustrated walkthrough, use VideoHelp's
[Dumping Your own L3 CDM with Android Studio](https://forum.videohelp.com/threads/408031-Dumping-Your-own-L3-CDM-with-Android-Studio).
The steps here are a brief backup for installing the tools and choosing an
emulator image; use this repository's commands for this fork.

## Install Android Studio

For emulator setup, download [Android Studio](https://developer.android.com/studio)
and follow Google's instructions for your computer. Check the linked OS and
hardware requirements before choosing an installer.

| Computer | Official installation guide | Basic steps |
| --- | --- | --- |
| Windows | [Windows installation](https://developer.android.com/studio/install#windows) | Download the Windows `.exe`, run it, then complete the Setup Wizard. |
| macOS | [Mac installation](https://developer.android.com/studio/install#mac) | Choose the Apple Silicon or Intel download, open the `.dmg`, drag Android Studio to Applications, and launch it. |
| Linux | [Linux installation](https://developer.android.com/studio/install#linux) | Extract the Linux `.tar.gz`, then launch `studio` from its `android-studio/bin/` directory. Follow Google's distribution-specific library requirements. |

The latest Studio release may require a newer OS than this project's Python
scripts. For older computers, check Google's
[Studio archive](https://developer.android.com/studio/archive) for a compatible
release and its requirements. Google currently lists Windows/Linux ARM hosts
as unsupported for Android Studio; that is separate from the
[ADB-only ARM setup](#arm-hosts).

<details>
<summary>📦 Optional Homebrew / Chocolatey installation</summary>

If you followed the [package-manager setup](setup.md#install-python-and-git),
you can install Studio through that manager instead of its website:

```sh
# macOS
brew install --cask android-studio
```

```powershell
# Windows: administrator PowerShell
choco install androidstudio -y
```

These use the [Homebrew cask](https://formulae.brew.sh/cask/android-studio) and
[Chocolatey package](https://community.chocolatey.org/packages/androidstudio).
Package-manager releases can lag Google's download. Open Android Studio after
installation and complete its Setup Wizard; installing the IDE alone does not
create a ready Android emulator.

</details>

### Install the SDK components

Open **SDK Manager** from the welcome screen's **More Actions** menu, or
**Tools → SDK Manager** inside Studio. In **SDK Tools**, install **Android SDK
Platform-Tools** and, when using an emulator, **Android Emulator**. Click
**Apply** and complete the downloads. Google's
[SDK Manager guide](https://developer.android.com/studio/intro/update#sdk-manager)
describes these components and updates.

Note the **Android SDK Location** shown there. Its `platform-tools` subfolder
contains ADB; add that folder to `PATH` using the instructions below. Then
create an emulator in **Device Manager** using the image guidance in the next
section. For a physical device, you can use standalone Platform-Tools without
installing Android Studio.

## Choose an emulator image

For Android Studio emulator testing across API 28–33, prefer **Services → Google
APIs** when selecting the system image. Root availability depends on the image's
build configuration, not just its Android/API version.

1. Open **Device Manager** in Android Studio and choose **Create Virtual Device**.
2. Select a phone profile, then choose an Android release. This fork's capture
   testing covers **Android 9–13 / API 28–33**.
3. Select **Google APIs**, not **Google Play Store**, under **Services**. Older
   Studio versions identify these in the image's name or target instead.
   Download an image compatible with your computer's architecture.
4. Finish creating the AVD and start it. Wait until the unlocked Android home
   screen is fully responsive, then verify root below.

See Google's [virtual-device guide](https://developer.android.com/studio/run/managing-avds)
if your Studio version's menus differ.

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
If you already installed them through Studio's SDK Manager, use that copy and
add it to `PATH`; a second installation is unnecessary. Google's
[Platform-Tools page](https://developer.android.com/tools/releases/platform-tools#downloads)
provides separate downloads for all three desktop operating systems.

| System | Installation |
| --- | --- |
| Windows | Download **SDK Platform-Tools for Windows** from [Android's official downloads](https://developer.android.com/tools/releases/platform-tools#downloads), extract the complete folder, and add the directory containing `adb.exe` to `PATH`. Alternatively, run `choco install adb -y` in administrator PowerShell using the [Chocolatey ADB package](https://community.chocolatey.org/packages/adb). Physical devices may also need a manufacturer's [USB driver](https://developer.android.com/studio/run/oem-usb). |
| macOS | Install the [Homebrew android-platform-tools cask](https://formulae.brew.sh/cask/android-platform-tools) with `brew install --cask android-platform-tools`, or use **SDK Platform-Tools for Mac** from [Android's downloads](https://developer.android.com/tools/releases/platform-tools#downloads). |
| Linux | Download **SDK Platform-Tools for Linux** from [Android's downloads](https://developer.android.com/tools/releases/platform-tools#downloads) and add the extracted directory to `PATH`, or install your distribution's ADB package. For USB permissions, follow Android's [Linux device setup](https://developer.android.com/studio/run/device#setting-up). |

<details>
<summary>🐧 Linux package-manager ADB commands</summary>

Use the row for your distribution. These install ADB from the distribution;
Studio's SDK Manager or Google's archive supplies the complete Platform-Tools
package.

| Distribution | Command | Package reference |
| --- | --- | --- |
| Ubuntu / Debian / Linux Mint | `sudo apt update` then `sudo apt install adb` | [Ubuntu](https://packages.ubuntu.com/search?keywords=adb&searchon=names&exact=1) · [Debian](https://packages.debian.org/stable/adb) |
| Fedora | `sudo dnf install android-tools` | [Fedora](https://packages.fedoraproject.org/pkgs/android-tools/android-tools/) |
| Arch Linux | `sudo pacman -Syu android-tools` | [Arch](https://archlinux.org/packages/extra/x86_64/android-tools/) |

Arch's `-Syu` also updates the system. Physical USB devices can require udev
rules or group membership; follow the Linux device setup link above instead
of running the dumper with `sudo`.

</details>

<details>
<summary>🛤️ Add an SDK Manager or extracted Platform-Tools folder to PATH</summary>

Use the actual folder containing `adb` / `adb.exe`, not the ZIP or its parent.
For an SDK Manager install, copy **Android SDK Location** and append
`platform-tools`. Keep the complete folder, including Windows DLLs.

**Windows:** search Start for **Edit environment variables for your account**.
Edit your user **Path**, choose **New**, and paste the full `platform-tools`
folder path. Save the dialogs and open a new PowerShell window.

**macOS:** for the usual SDK location, add this line to `~/.zshrc`:

```sh
export PATH="$HOME/Library/Android/sdk/platform-tools:$PATH"
```

**Linux:** for the usual SDK location, add this line to `~/.bashrc` (or
`~/.zshrc` if using zsh):

```sh
export PATH="$HOME/Android/Sdk/platform-tools:$PATH"
```

Replace the example directory if you moved the SDK or used a standalone
download, keeping it quoted when its path contains spaces. Open a new terminal
after saving. See Google's [SDK environment-variable guide](https://developer.android.com/tools/variables).
Package-manager installations normally expose `adb` on `PATH` already.

</details>

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
