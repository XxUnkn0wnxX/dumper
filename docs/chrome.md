# 🌐 Chrome test-browser setup

[← Project overview](../README.md) · [Dumper usage](dumper.md) · [Full auto](full-auto.md)

Both manual dumper runs and full auto use the same browser setup. Before opening
the configured test page, the launcher applies testing flags to suppress Chrome's
first-run screens, startup promotions, notification onboarding, and supported
help bubbles. It then force-stops Chrome and launches the page afresh using
`am start -f 0x10000000` (`FLAG_ACTIVITY_NEW_TASK`) targeting `com.android.chrome`,
which asks Android to bring Chrome's task to the foreground. This intent flag has
existed since API 1. If Android explicitly rejects the launch option, the dumper
warns and tries one normal launch without the focus flag. Timeouts, connection
failures, and permission errors do not trigger a second launch. Keep the device
unlocked; Android permission dialogs can still appear above the browser.

The target must be the selected, online Android device with `com.android.chrome`
installed and enabled. This works through ADB; it does not depend on a Pixel model
or tap coordinates. See [test-page configuration](dumper.md#automatic-test-page-launch)
for the single active URL and manual browser options.

## ⚙️ Settings applied automatically

| Setting | Purpose and effect |
| --- | --- |
| `am set-debug-app --persistent com.android.chrome` | Selects Chrome as Android's debug app so supported builds read testing flags while ADB debugging is enabled. Replaces the previous debug app and persists across reboots. Does not select “Wait for debugger.” |
| `--disable-fre` | Skips Android Chrome's first-run experience, including the welcome and first-run sign-in flow. |
| `--no-first-run` | Retained compatibility switch; Android's first-run skip is provided by `--disable-fre`. |
| `--disable-startup-promos-for-testing` | Suppresses Chrome's startup promo flow, including supported sign-in and other startup offers. |
| `--disable-default-browser-promo` | Suppresses the Android default-browser promotion on builds that implement this switch. |
| `--propagate-iph-for-testing` | With **no value**, suppresses in-product help through Chrome's feature-engagement system on builds that support it. Replaces an existing value that would force a particular tutorial. |
| `--enable-features=NotificationPermissionVariant:permission_request_max_count/0` | Sets Chrome's app-notification onboarding prompt limit to zero. Suppresses the “Chrome notifications make things easier” flow without granting or revoking Android notification permission. |
| `--enable-features=DisablePrivacySandboxPrompts` | Enables Chrome's dedicated Privacy Sandbox prompt-suppression control on builds that still have that onboarding flow. This feature's name is negative: it must be **enabled** to suppress prompts. |
| `--autoplay-policy=no-user-gesture-required` | Allows autoplay without an initial tap. The page must still request playback. |

The two enabled features share **one** `--enable-features` argument in the
written file. Existing unrelated enabled/disabled features are retained, and
conflicting entries for the managed features are replaced. Unrelated switches,
desktop-mode settings, and user-agent settings are preserved. Repeated launches
do not keep appending duplicate managed flags.

Flags are stored in `/data/local/tmp/chrome-command-line` with mode `0644` and
remain for subsequent Chrome launches until removed. The launcher does not clear
browsing data, change Android permission grants, sign into an account, select a
default browser or search provider, change `ro.debuggable`, or restart ADB/Frida.

## Post-readiness warning and refresh

After successful hook readiness, the dumper's normal progress check waits about
35 seconds before acting; time spent in automatic browser startup is included,
and the check runs when that startup call returns. If no completed, verified
pair exists, it emits one warning and retains the RSA debug/client logs. The
warning is generic when no RSA key has arrived and keeps the layout advice when
RSA output is present. Save/write failures keep their specific diagnostic
instead of adding this general waiting hint.

When this run successfully launched Chrome, the dumper then checks that the
focused window belongs exactly to `com.android.chrome`. If it does, it makes
one foreground-tab refresh with `adb -s SELECTED_SERIAL shell input keyevent
KEYCODE_F5`. It never retries, force-stops, relaunches, or creates a tab for
this recovery attempt. It skips the attempt for `--no-browser`, a failed or
skipped automatic launch, an already-saved pair, another focused application,
an Android permission window, or an unknown focus. The dumper continues waiting
indefinitely while the session remains healthy. This refresh changes no
persistent Chrome setting, so the existing undo instructions below do not need
an additional step.

Manual and full-auto runs use this dumper-owned warning and refresh behavior.
Full auto mirrors the dumper status event and does not add an independent timer
or refresh attempt.

## 📱 Older and newer Chrome

The same set is applied generally. Chromium stores unrecognized switches, and
feature overrides only affect code that reads the corresponding feature. An
older build therefore ignores controls it does not implement; a newer build can
ignore a control removed along with an obsolete onboarding flow. There is no
extra device-version query or separate Pixel-specific branch.

Source review on **2026-09-20** covers the Chrome 69 command-line/feature parser,
Chrome 109's Android notification/startup controls, and Android Stable
**153.0.8010.52** (current at review) plus Chromium's main branch.
This is source compatibility evidence, **not a live
test of every Chrome/Android combination**. The reported notification screen was
on Android 13/API 33 with Chrome 109.0.5414.123.

Onboarding suppression depends on Chrome continuing to honor these controls.
Website dialogs, protected-content permissions, camera/microphone/location
permissions, device unlock screens, and vendor/Android setup screens can still
need user input. The launcher does not automatically accept those choices.
Allowing autoplay does not press a website's custom Load/Play button or solve
browser challenges. A successful URL-open log does not prove playback started.

Missing ADB/Chrome, device mismatches, timeouts, or launch errors produce a
warning; capture remains available for manual playback.

## ↩️ Undo on an emulator or real phone

Stop the dumper first. Use `python dump_keys.py --no-browser` on later manual
runs if you do not want browser settings reapplied. Full auto applies them again
through its dumper child. Replace `emulator-5554` with your phone's ADB serial.

<details>
<summary>Remove the testing settings while keeping unrelated Chrome flags</summary>

Copy the current file to the repository's scratch folder. On macOS/Linux:

```sh
mkdir -p .tmp
adb -s emulator-5554 pull /data/local/tmp/chrome-command-line .tmp/chrome-command-line
```

On Windows PowerShell, create the folder with
`New-Item -ItemType Directory -Force .tmp`, then run the same `adb pull` command.

Edit `.tmp/chrome-command-line`:

1. Remove `--disable-fre`, `--no-first-run`,
   `--disable-startup-promos-for-testing`, `--disable-default-browser-promo`,
   `--propagate-iph-for-testing`, and
   `--autoplay-policy=no-user-gesture-required`.
2. In the comma-separated `--enable-features` value, remove
   `NotificationPermissionVariant:permission_request_max_count/0` and
   `DisablePrivacySandboxPrompts`. Keep unrelated entries; remove the entire
   switch only if its list becomes empty.
3. Keep the initial executable placeholder (`_` or the original name), unrelated
   switches, and unrelated `--disable-features` entries. Restore any previous
   custom values for managed switches/features if applicable.

Apply the edited file and clear the debug-app selection:

```sh
adb -s emulator-5554 push .tmp/chrome-command-line /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell chmod 644 /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell am clear-debug-app
adb -s emulator-5554 shell am force-stop com.android.chrome
```

If the file contained only the dumper's settings, you can instead remove it:

```sh
adb -s emulator-5554 shell rm /data/local/tmp/chrome-command-line
adb -s emulator-5554 shell am clear-debug-app
adb -s emulator-5554 shell am force-stop com.android.chrome
```

`am clear-debug-app` clears the current debug-app selection; it does not restore
the previous app. If needed, reselect it under **Developer options → Select
debug app**, including the previous “Wait for debugger” preference. Previous
managed flag values and debug-app selection are not backed up by the launcher.
These steps do not clear browsing data or undo choices already saved by Chrome.

</details>

## 🛠️ Maintainer references

Browser policy and merging live in [`Helpers/Browser.py`](../Helpers/Browser.py).
Keep onboarding controls together there, verify the Android execution path
before adding a switch, and extend [`tests/test_browser.py`](../tests/test_browser.py)
when changing list merging or ownership. Desktop-only flags should not be added
as presumed Android fixes.

<details>
<summary>Chromium source and testing documentation</summary>

- [Chrome 109 notification prompt controller](https://github.com/chromium/chromium/blob/109.0.5414.123/chrome/browser/notifications/android/java/src/org/chromium/chrome/browser/notifications/permissions/NotificationPermissionController.java): `permission_request_max_count` governs both the rationale and the controller's Android permission request.
- [Android Chrome keyboard shortcuts](https://github.com/chromium/chromium/blob/109.0.5414.123/chrome/android/java/src/org/chromium/chrome/browser/KeyboardShortcuts.java): an unmodified F5 requests a normal reload of the current tab. The same route was checked in Chrome 69 and 153.
- [Android's new-task launch behavior](https://developer.android.com/reference/android/content/Intent#FLAG_ACTIVITY_NEW_TASK): starts the activity in a task or brings its existing task to the foreground.
- [ADB intent arguments](https://developer.android.com/tools/adb#IntentSpec): pass the numeric intent flags with `-f`; `am` does not provide a `--activity-new-task` option.
- [Chrome 153 Android switches](https://github.com/chromium/chromium/blob/153.0.8010.52/chrome/browser/flags/android/java_templates/ChromeSwitches.java.tmpl) and [feature-engagement documentation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/feature_engagement/README.md): startup and in-product-help controls.
- [Chrome 153 startup promo gate](https://github.com/chromium/chromium/blob/153.0.8010.52/chrome/android/java/src/org/chromium/chrome/browser/tabbed_mode/TabbedRootUiCoordinator.java) and [Android default-browser promo gate](https://github.com/chromium/chromium/blob/153.0.8010.52/chrome/browser/ui/android/default_browser_promo/java/src/org/chromium/chrome/browser/ui/default_browser_promo/DefaultBrowserPromoUtils.java): the Android code checks the dedicated suppression switches before showing these offers.
- [Chrome 109 Privacy Sandbox feature definition](https://github.com/chromium/chromium/blob/109.0.5414.123/components/privacy_sandbox/privacy_sandbox_features.cc) and [prompt gate](https://github.com/chromium/chromium/blob/109.0.5414.123/chrome/browser/privacy_sandbox/privacy_sandbox_service.cc): the enabled suppression feature returns no required prompt; it is absent from Chrome 153 after that onboarding's retirement.
- [Chrome 69 feature handling](https://github.com/chromium/chromium/blob/69.0.3497.100/base/feature_list.cc) and [command-line handling](https://github.com/chromium/chromium/blob/69.0.3497.100/base/command_line.cc): unused overrides and switches do not select browser behavior.
- [Android Stable release metadata](https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Android&num=1), [Android activity-manager commands](https://developer.android.com/tools/adb#am), and [Chrome autoplay testing](https://developer.chrome.com/blog/autoplay/#developer-switches).

</details>
