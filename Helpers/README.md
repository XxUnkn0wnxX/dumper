# Protobuf maintenance

The repository ships `wv_proto2_pb2.py` and pins its supported Python Protobuf
runtime in `requirements.txt`. Normal installation uses that generated file;
users do not need `protoc` or a generation step.

`wv_proto2.proto` is the editable schema. Its `proto2` syntax is independent of
the compiler and Python runtime versions. It has no schema imports, so this is
the only `.proto` file needed to regenerate the binding. Do not edit the generated
Python file by hand.

## Optional regeneration

Use Python 3.10 or newer, install the project requirements into `.venv`, and have
the desired `protoc` compiler on `PATH`. The initial migration was validated with
`protoc 36.2` and Python `protobuf==7.36.2`. The generated file's header records
its required Python Protobuf version; `requirements.txt` records the shipped pin.

From the repository root:

```sh
.venv/bin/python tools/regenerate_protobuf.py --update-runtime
```

The helper generates a temporary binding, reads its Python Protobuf version,
installs that exact runtime into the virtual environment, validates the generated
import, and updates both `Helpers/wv_proto2_pb2.py` and the exact Protobuf pin in
`requirements.txt`. Other dependencies are unchanged. It makes no Git commits.
Use `--protoc /path/to/protoc` to select a compiler explicitly.

Omit `--update-runtime` to regenerate using an already compatible environment.
The helper refuses to replace the output files if generation or import validation
fails. If the optional pip step succeeded before a later failure, the environment
remains updated; the helper does not downgrade it automatically.

To check the generated file and dependency pin without replacing either:

```sh
.venv/bin/python tools/regenerate_protobuf.py --check
```

This regenerates under ignored `tmp/` and compares the results byte for byte.
Use the same compiler version recorded in the last generation to reproduce the
checked-in output; changing compiler versions can change generated code even when
the schema is unchanged. `--check` never installs packages. All helper modes
resolve repository paths from the script, so they also work from another directory.

After regeneration, run the regression suite and dependency check:

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip check
```

`tests/test_protobuf.py` checks the complete legacy schema, synthetic request bytes
serialized with the original binding and Protobuf 3.19.3, proto2 field presence,
unknown fields, and the dumper's certificate/key matching. It neither reads real
device captures nor writes key dumps. Intentional schema changes require reviewing
these compatibility expectations; a compiler/runtime update alone should preserve
them. Live device operation still needs a separate smoke test.

## Source provenance

The original ZIP bundles were obtained from:

- [CrymanChen/WKS-KEYS GitHub releases](https://github.com/CrymanChen/WKS-KEYS/releases):
  `WKS-KEYS (Version 2023-04-07).zip`.
- [VideoHelp: WKS_KEYS updated protobuf to version 4](https://forum.videohelp.com/threads/411509-WKS_KEYS-updated-protobuf-to-version-4):
  `WKS-KEYS.zip` and `WKS-KEYS_L3_correction.zip`.

The schema was copied unchanged from `WKS-KEYS (Version 2023-04-07).zip`, member:

```text
pywidevine/L3/cdm/formats/wv_proto2.proto
```

Original schema SHA-256:

```text
ab06120baccfb59f27bb87a50d235ef00bc690af452703a7f9018ecf1f0b4d49
```

The supplied `WKS-KEYS.zip` and `WKS-KEYS_L3_correction.zip` archives contain the
same schema. Their accompanying old `wv_proto2_pb2.py` files are byte-identical to
the dumper binding before regeneration. The regenerated schema preserves all
message definitions; its descriptor filename now identifies `Helpers/wv_proto2.proto`.

The [local protobuf-source archive collection](../archives/wks-keys/README.md)
keeps historical protobuf-only repacks of the supplied bundles, including an exact
copy of this schema member. The archives are provenance references; regeneration
uses the checked-in `Helpers/wv_proto2.proto`, and normal users do not need them.

The [original regeneration discussion](https://forum.videohelp.com/threads/409040-Correcting-Protobuf-Downgrade-to-3-19-0-error)
explains why WKS-KEYS has the schema omitted from the original dumper distribution.
The [later updated bundles](https://forum.videohelp.com/threads/411509-WKS_KEYS-updated-protobuf-to-version-4)
also contain `wv_proto4.proto`, but that is a renamed, different proto3 schema.
It is not needed for this dumper's existing proto2 contract.
