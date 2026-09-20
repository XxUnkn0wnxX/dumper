# 🧬 Protobuf maintenance

[← Back to the Dumper README](../README.md) · [🧰 Maintainer tools](../tools/README.md#protobuf-regeneration) · [📦 Archive inventory](../archives/wks-keys/README.md)

The repository ships [`wv_proto2_pb2.py`](wv_proto2_pb2.py) and pins its supported
Python Protobuf runtime in [`requirements.txt`](../requirements.txt). Normal installation uses that generated file;
users do not need `protoc` or a generation step.

[`wv_proto2.proto`](wv_proto2.proto) is the editable schema. Its `proto2` syntax
is independent of the compiler and Python runtime versions. It has no schema
imports, so this is the only `.proto` file needed to regenerate the binding. Do
not edit the generated Python file by hand.

## Optional regeneration

The commands, compiler/runtime requirements, helper options, and validation
steps are maintained in the [tools guide](../tools/README.md#protobuf-regeneration).
The schema and generated binding stay in this directory; their source provenance
is recorded below.

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
same schema. Their accompanying old `wv_proto2_pb2.py` files are byte-identical to
the dumper binding before regeneration. The regenerated schema preserves all
message definitions; its descriptor filename now identifies `Helpers/wv_proto2.proto`.

The [local protobuf-source archive collection](../archives/wks-keys/README.md)
keeps historical protobuf-only repacks of the supplied bundles, including an exact
copy of this schema member. The archives are provenance references; regeneration
uses the checked-in `Helpers/wv_proto2.proto`, and normal users do not need them.

The [original regeneration discussion](https://forum.videohelp.com/threads/409040-Correcting-Protobuf-Downgrade-to-3-19-0-error)
explains why WKS-KEYS has the schema omitted from the original dumper distribution.

<details>
<summary>🧭 Historical note: the later proto4 schema</summary>

The [later updated bundles](https://forum.videohelp.com/threads/411509-WKS_KEYS-updated-protobuf-to-version-4)
also contain `wv_proto4.proto`, but that is a renamed, different proto3 schema.
It is not needed for this dumper's existing proto2 contract.

</details>
