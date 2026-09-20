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

The checked-in protobuf binding uses the exact runtime version pinned in
`requirements.txt`. The compatibility tests require no compiler; optional
regeneration checks are documented in [Protobuf maintenance](tools/README.md#protobuf-regeneration).

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

Run the protobuf schema, legacy serialization, and request-handler regressions:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_protobuf.py' -v
```

For the Frida setup helper's focused tests and live device checks, see the
[helper guide](tools/README.md#cleanup-and-maintainer-checks). Its mocked tests
are also included in the full suite above.

## Additional checks

Compile the Python files without running the dumper:

```sh
.venv/bin/python -m compileall -q Helpers dump_keys.py tests tools
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
- Preserving the full legacy protobuf schema and parsing synthetic requests
  serialized with the original Protobuf 3.19.3 binding, including field presence,
  unknown fields, and certificate/key matching without writing output files.

The JavaScript harness executes the actual hook script with simulated Frida APIs.
It checks both verified signatures, all manual labels, rejection of changed or
ambiguous signatures before hooks are installed, exclusion of data exports, and
request-hook attachment failures.

`tests/fixtures/cdm_signatures.json` contains signatures extracted from 12 ELF
libraries across eight Android 9–13 SDK packages, including Android 12L. Each
fixture records its source package/revision, library SHA-256, architecture's
pointer size, and the first output argument's position. The harness exercises
each sample and rejects altered signatures and conflicting recognized layouts.
Neither SDK images nor library binaries are needed to run the tests.

No connected device, running Frida server, or ADB connection is required.
The tests do not access real devices or produce key dumps. Live device discovery,
key extraction, automatic signature detection, and compatibility with a new
Widevine library still require separate verification on the target device.
