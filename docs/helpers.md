# 🧩 Shared Python helpers

[← Back to the Dumper README](../README.md) · [🧬 Schema and regeneration](protobuf.md) · [📦 Archive inventory](../archives/wks-keys/README.md)

`Helpers/` contains the checked-in [`wv_proto2.proto`](../Helpers/wv_proto2.proto)
schema and generated [`wv_proto2_pb2.py`](../Helpers/wv_proto2_pb2.py) binding used by the
dumper. Normal users use the generated binding and do not need `protoc`.

For regeneration arguments, runtime compatibility, schema provenance, and the
historical source archives, read the [Protobuf guide](protobuf.md).
Do not edit the generated Python file by hand.

WVD generation is a focused exception to the shared main-venv behavior:
`tools/generate_wvd.py` requires the strict `.venv-wvd` bootstrap described in
the [WVD environment boundary](wvd.md#environment-boundary).

Shared Python CLI support also lives in `Helpers/`:

| Module | Purpose | Guide |
| --- | --- | --- |
| [`Bootstrap.py`](../Helpers/Bootstrap.py) | Initialize and enter the project venv when a CLI is launched outside any venv. | [Python setup](setup.md#automatic-environment-setup) |
| [`WvdBootstrap.py`](../Helpers/WvdBootstrap.py) | Check and enter the dedicated `.venv-wvd` using shared initialization. | [WVD setup](wvd.md#environment-boundary) |
| [`CLI.py`](../Helpers/CLI.py) | Repair terminal flags and protect cancellation cleanup. | [Cancellation behavior](frida-setup.md#cancellation-and-cleanup) |
| [`AutoInit.py`](../Helpers/AutoInit.py) | Run shared initialization in full auto's background initialization stage. | [Full auto](full-auto.md) |
| [`AutoProcesses.py`](../Helpers/AutoProcesses.py) | Own and stop background child processes, including Windows Job Objects. | [Full auto](full-auto.md) |
| [`AutoSession.py`](../Helpers/AutoSession.py) | Pass per-run readiness and verified-pair metadata to the controller. | [Full auto](full-auto.md) |
| [`AutoLogging.py`](../Helpers/AutoLogging.py) | Preserve full raw logs, mirror the controller, and prevent concurrent log overwrites. | [Full auto](full-auto.md) |
