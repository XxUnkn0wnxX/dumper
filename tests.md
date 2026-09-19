# Local tests

Run these commands from the repository root, where `dump_keys.py` and
`requirements.txt` are located. The examples use macOS/Linux shell commands.
The tests run locally with Python's built-in `unittest`; no GitHub Actions
setup is required.

## Setup

Reuse the project's existing `.venv`. If it does not exist, create it first:

```sh
python3 -m venv .venv
```

Install the project dependencies into that environment:

```sh
.venv/bin/python -m pip install --upgrade -r requirements.txt
```

The test commands below use `.venv/bin/python` directly, so activating the
environment is optional. No separate test-runner package is needed.

## Run all tests

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Each test is listed with its result. A successful run ends with `OK` and exits
with status `0`; a failing run reports `FAIL` or `ERROR` and exits nonzero.

The existing protobuf dependency and generated bindings may emit deprecation
warnings on newer Python versions. Those warnings alone do not indicate a
failed test; check the final test result.

The Python suite includes the JavaScript detection wrapper. When Node.js is
available it runs `tests/test_cdm_detection.js`; without Node.js that wrapper
skips the JavaScript check.

## Run a focused check

Run only the device-selection test file:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_device_selection.py' -v
```

Run only the regression that rejects an explicitly selected iPhone before any
process scan or attachment:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_device_selection.py' -k explicit_iphone -v
```

Run the CDM layout, hook lifecycle, and CLI regressions:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_cdm_cli.py' -v
```

Run the JavaScript harness directly when Node.js is installed:

```sh
node tests/test_cdm_detection.js
```

## Additional checks

Compile the Python files without running the dumper:

```sh
.venv/bin/python -m compileall -q Helpers/Device.py Helpers/DeviceSelection.py dump_keys.py tests
```

Check the installed dependency versions for conflicts:

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

The JavaScript harness executes the actual hook script with simulated Frida APIs.
It checks the verified signature, all manual labels, rejection of changed or
ambiguous signatures before hooks are installed, exclusion of data exports, and
request-hook attachment failures.

No connected device, running Frida server, or ADB connection is required.
The tests do not access real devices or produce key dumps. Live device discovery,
key extraction, automatic signature detection, and compatibility with a new
Widevine library still require separate verification on the target device.
