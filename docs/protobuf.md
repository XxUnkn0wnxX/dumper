# 🧬 Protobuf schema and regeneration

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [📦 Archive inventory](../archives/wks-keys/README.md)

The repository ships [`Helpers/wv_proto2_pb2.py`](../Helpers/wv_proto2_pb2.py)
and pins its supported Python Protobuf runtime in
[`requirements.txt`](../requirements.txt). Normal installation uses that
generated file; users do not need `protoc` or a generation step.

[`Helpers/wv_proto2.proto`](../Helpers/wv_proto2.proto) is the editable schema.
Its `proto2` syntax is independent of compiler and Python runtime versions. It
has no schema imports, so it is the only `.proto` input needed for regeneration.
Do not edit the generated Python file by hand.

## Protobuf regeneration

[`tools/regenerate_protobuf.py`](../tools/regenerate_protobuf.py) rebuilds the
shipped binding from the checked-in schema and keeps the exact runtime pin in
`requirements.txt` aligned. Use Python 3.10 or newer, install the project
requirements into `.venv`, and put the desired `protoc` compiler on `PATH`.
Outside any venv, the shared
[automatic initialization](setup.md#automatic-environment-setup) prepares
`.venv` and restarts the command there. An active custom venv is used as-is.
The initial migration was validated with `protoc 36.2` and
`protobuf==7.36.2`; the generated file's header records its required Python
Protobuf version.

From the repository root:

```sh
python tools/regenerate_protobuf.py --update-runtime
```

With no mode flag, the helper uses `protoc` from `PATH`, validates the generated
binding with the current Python environment, and replaces changed outputs. It
does not change the runtime after initialization. `--check` and `--update-runtime` are mutually
exclusive.

| Argument | Description | Default | Example usage |
| --- | --- | --- | --- |
| *(no option)* | Regenerate, validate, and replace changed outputs. | Normal regeneration mode | `python tools/regenerate_protobuf.py` |
| `-h`, `--help` | Show the complete helper help and exit. | — | `python tools/regenerate_protobuf.py --help` |
| `--protoc PATH` | Use a specific `protoc` executable instead of the one found on `PATH`. | `protoc` | `python tools/regenerate_protobuf.py --protoc /opt/homebrew/bin/protoc` |
| `--check` | Regenerate under ignored `.tmp/` and compare the binding and runtime pin without replacing either; mutually exclusive with `--update-runtime`. | Off | `python tools/regenerate_protobuf.py --check` |
| `--update-runtime` | Install the generated binding's exact Protobuf version in the virtual environment running the helper before updating tracked outputs; requires a virtual environment and is mutually exclusive with `--check`. | Off | `python tools/regenerate_protobuf.py --update-runtime` |

With `--update-runtime`, the helper generates a temporary binding, reads its
Python Protobuf version, installs that exact runtime into the virtual
environment, validates the generated import, and updates both
`Helpers/wv_proto2_pb2.py` and the exact Protobuf pin in `requirements.txt`.
Other dependencies are unchanged. It makes no Git commits.

Omit `--update-runtime` to regenerate using an already compatible environment.
The helper refuses to replace output files if generation or import validation
fails. If the optional pip step succeeds before a later failure, the environment
remains updated; the helper does not downgrade it automatically.

Pressing **Ctrl+C** during regeneration returns status `130` after cleaning the
temporary staging directory. If interruption occurs while replacing tracked
outputs, the previous `Helpers/wv_proto2_pb2.py` and `requirements.txt` contents
are restored together. A warning identifies any filesystem error that prevents
cleanup or restoration. A successful `pip --update-runtime` change is an
environment change and is not rolled back by later cancellation or failure.

To check the generated file and dependency pin without replacing either:

```sh
python tools/regenerate_protobuf.py --check
```

This regenerates under ignored `.tmp/` and compares results byte for byte. The
helper creates `.tmp/` automatically and removes its temporary working
directory afterward. Use the same compiler version recorded in the last
generation to reproduce checked-in output; changing compiler versions can
change generated code even when the schema is unchanged. `--check` does not
install the generated runtime; initial environment setup may still install
the project's existing requirements. All helper modes resolve repository
paths from the script.

After regeneration, run the regression suite and dependency check:

```sh
python -m unittest discover -s tests -v
python -m pip check
```

The compatibility tests check the complete legacy schema, synthetic request
bytes serialized with the original Protobuf 3.19.3 binding, proto2 field
presence, unknown fields, and certificate/key matching. They neither read real
device captures nor write key dumps. Intentional schema changes require review;
a compiler/runtime update alone should preserve these compatibility expectations.

## Source provenance

The original ZIP bundles were obtained from these sources:

| Source | Original bundle names |
| --- | --- |
| [CrymanChen/WKS-KEYS GitHub releases](https://github.com/CrymanChen/WKS-KEYS/releases) | `WKS-KEYS (Version 2023-04-07).zip` |
| [VideoHelp: WKS_KEYS updated protobuf to version 4](https://forum.videohelp.com/threads/411509-WKS_KEYS-updated-protobuf-to-version-4) | `WKS-KEYS.zip`, `WKS-KEYS_L3_correction.zip` |

The schema was copied unchanged from `WKS-KEYS (Version 2023-04-07).zip`, member:

```text
pywidevine/L3/cdm/formats/wv_proto2.proto
```

Original schema SHA-256:

```text
ab06120baccfb59f27bb87a50d235ef00bc690af452703a7f9018ecf1f0b4d49
```

The supplied `WKS-KEYS.zip` and `WKS-KEYS_L3_correction.zip` archives contain the
same schema. Their accompanying old `wv_proto2_pb2.py` files are byte-identical
to the dumper binding before regeneration. The regenerated schema preserves all
message definitions; its descriptor filename identifies
`Helpers/wv_proto2.proto`.

The [local protobuf-source archive collection](../archives/wks-keys/README.md)
keeps historical protobuf-only repacks of the supplied bundles, including an
exact copy of this schema. The archives are provenance references; regeneration
uses the checked-in schema, and normal users do not need the archives.

The [original regeneration discussion](https://forum.videohelp.com/threads/409040-Correcting-Protobuf-Downgrade-to-3-19-0-error)
explains why WKS-KEYS has the schema omitted from the original dumper
distribution.

<details>
<summary>🧭 Historical note: the later proto4 schema</summary>

The [later updated bundles](https://forum.videohelp.com/threads/411509-WKS_KEYS-updated-protobuf-to-version-4)
also contain `wv_proto4.proto`, but that is a renamed, different proto3 schema.
It is not needed for this dumper's existing proto2 contract.

</details>
