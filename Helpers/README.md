# 🧬 Protobuf helper files

[← Back to the Dumper README](../README.md) · [🧬 Schema and regeneration](../docs/protobuf.md) · [📦 Archive inventory](../archives/wks-keys/README.md)

This directory contains the checked-in [`wv_proto2.proto`](wv_proto2.proto)
schema and generated [`wv_proto2_pb2.py`](wv_proto2_pb2.py) binding used by the
dumper. Normal users use the generated binding and do not need `protoc`.

For regeneration arguments, runtime compatibility, schema provenance, and the
historical source archives, read the [Protobuf guide](../docs/protobuf.md).
Do not edit the generated Python file by hand.

Shared Python CLI support also lives here:

| Module | Purpose | Guide |
| --- | --- | --- |
| [`Bootstrap.py`](Bootstrap.py) | Initialize and enter the project venv when a CLI is launched outside any venv. | [Python setup](../docs/setup.md#automatic-environment-setup) |
| [`CLI.py`](CLI.py) | Repair terminal flags and protect cancellation cleanup. | [Cancellation behavior](../docs/frida-setup.md#cancellation-and-cleanup) |
