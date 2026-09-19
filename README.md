# Dumper

Dumper is a Frida script to dump L3 CDMs from rooted Android devices.

## ** IMPORTANT **
The `--cdm-version` flag controls the `PrepareKeyRequest` argument layout and is independent of Android and Frida version numbers. It defaults to `auto`: the Frida script checks the exported C++ signature before attaching hooks and selects a known layout. This identifies the argument layout, not an exact CDM or plugin version.

Automatic detection recognizes two signatures verified in libraries extracted from Android 9–13 SDK images, including Android 12L. They select `args[4]` or `args[5]` according to the library's actual signature. These checks are offline; live automatic detection still needs verification. An unknown, missing, or ambiguous signature prevents hooking that library and reports an error. Other matching libraries are still tried; startup exits if none can be hooked.

Manual labels `14.0.0`, `15.0.0`, and `16.0.0` select `args[4]`; `16.1.0` and `17.0.0` select `args[5]`. These remain available to override automatic selection when you know the correct layout for a particular library.

## Prerequisites
- Rooted Android device
- [Installed Frida server on the Android device](https://frida.re/docs/android/)
- Installed [platform-tools ADB/Fastboot](https://developer.android.com/studio/releases/platform-tools) on the PC
- Installed [Python 3](https://www.python.org/downloads/) on the PC
- A known `PrepareKeyRequest` layout, if automatic detection cannot verify the library signature.

## Requirements:
Create and activate a virtual environment, then install the dependencies:

```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade -r requirements.txt
```

The `frida`, `frida-tools`, and `pycryptodome` requirements are unpinned, so `--upgrade` asks pip for the latest compatible releases. `frida-tools` provides the Frida CLI. Use an Android `frida-server` build that matches the installed `frida` package.

## Usage:

* Enable USB debugging on the Android device and connect it to the PC
* [Start frida-server on the Android device](https://frida.re/docs/android/)
* Execute dump_keys.py on the PC
* Start streaming some DRM-protected content on the Android device, e.g. [Bitmovin](https://bitmovin.com/demos/drm) or the [DASH-IF Widevine demo](https://reference.dashif.org/dash.js/v4_latest/samples/drm/widevine.html)

At startup, the dumper automatically selects a USB Frida device whose system metadata reports Android; iPhones and other devices are ignored. If more than one Android device is connected, run `frida-ls-devices` to find their IDs and select one explicitly, for example (with `.venv` activated):
```
python3 dump_keys.py --device-id emulator-5554
```

Run the local regression tests with `.venv/bin/python -m unittest discover -s tests -v`. See [tests.md](tests.md) for setup, focused checks, and coverage.

The primary command uses automatic layout detection and scans exported candidate functions whose names contain only lowercase letters in the Widevine `libwvhidl.so` and `libwvaidl.so` modules:
```
python3 dump_keys.py
```

If a library signature is unknown, automatic detection refuses to hook that library. If no supported library remains, startup exits with an error. After investigating a specific library, you can provide a known manual layout override, for example:
```
python3 dump_keys.py --cdm-version 17.0.0
```

You can pass the function name to hook using the `--function-name` argument. Names depend on the library build; `zrtoooke` is one of the known candidates in the tested Android 13 library. You can use [this post](https://forum.videohelp.com/threads/404219-How-To-Dump-L3-CDM-From-Android-Device-s-(ONLY-Talk-About-Dumping-L3-CDMS)/page6#post2646150) to identify candidates for other builds.
```
python3 dump_keys.py --cdm-version 17.0.0 --function-name 'zrtoooke'
```

You can pass one or more `.so` module names after a single `--module-name` argument. By default it looks in the `libwvhidl.so` and `libwvaidl.so` files. The name can change depending on the version and SoC, including but not limited to: `libwvaidl.so`, `libwvhidl.so`, `libwvdrmengine.so`, `libwvm.so`, `libdrmwvmplugin.so` [source](https://arxiv.org/abs/2204.09298). You can find your module name in the `/vendor/lib64/` or `/vendor/lib/` directories using an ADB shell.

```
python3 dump_keys.py --cdm-version 17.0.0 --module-name 'libwvhidl.so' 'libwvaidl.so'
```


## Options:
```
    -h, --help                      Print this help text and exit.
    --cdm-version                   PrepareKeyRequest layout: auto (default) or a known manual label.
    --device-id                     The Frida USB device ID (see frida-ls-devices).
    --function-name                 The name of the function to hook to retrieve the private key.
    --module-name                   The name of the widevine `.so` modules.
```

## Scenario:
1. You've got the function name
2. You've got the private key
3. Client ID extracted
4. Script closed

The `client_id.bin` and `private_key.pem` pair is written only after a matching client ID and private key have both been received. Files are saved under `key_dumps/<device>/private_keys/<system-id>/<key-prefix>/`, where `<system-id>` comes from the client ID and `<key-prefix>` is the first 10 characters of the RSA key modulus. The log reports the save path when the pair is written.

## Recommended setup

A rooted Pixel device or Pixel emulator profile running Android 13 or earlier is recommended. Dumping with the manual `17.0.0` setting worked on the reported Pixel 6 Pro Android 13 setup. Automatic detection has been checked offline against its saved library and 12 libraries from eight SDK image packages. Android 14 and later are outside the current verified scope.

The SDK samples cover the following builds. This records the observed signatures; Android/API numbers do not drive selection or establish an exact CDM version. Other library builds may differ.

| Android release | API | Library architecture | Detected output argument |
| --- | --- | --- | --- |
| Android 9 | 28 | x86, 32-bit | `args[4]` |
| Android 10 | 29 | x86, 32-bit | `args[4]` |
| Android 11 | 30 | x86, 32-bit | `args[4]` |
| Android 12 | 31 | x86-64, 64-bit | `args[5]` |
| Android 12L | 32 | x86-64, 64-bit | `args[5]` |
| Android 13 | 33 | x86-64, 64-bit | `args[5]` |

The samples include both Google APIs and Google Play variants for API 28 and 33,
Google Play images for API 29–32, and the additional `libwvdrmengine.so` copies
present in API 29–32. The default module names remain `libwvhidl.so` and
`libwvaidl.so`. Test fixtures record the SDK package revisions, library hashes,
and exact exported signatures without including the library binaries.

## Temporary disabling L1 to use L3 instead
A few phone brands let us use the L1 keybox even after unlocking the bootloader (like Xiaomi). In this case, installation of a Magisk module called [liboemcrypto-disabler](https://github.com/umylive/liboemcrypto-disabler) is necessary.

## Credits
Thanks to the original author of the code.
