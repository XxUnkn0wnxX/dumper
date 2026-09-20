# 📦 Archived WKS-KEYS protobuf sources

[← Back to the Dumper README](../../README.md) · [🧬 Protobuf maintenance](../../docs/protobuf.md#source-provenance)

These ZIPs preserve the protobuf sources and historical generated Python modules
from the three supplied WKS-KEYS bundles. They provide local reference copies for
the [protobuf maintenance guide](../../docs/protobuf.md#source-provenance), so
maintainers can inspect the original schema without downloading the bundles again.

Regeneration uses the editable [Helpers/wv_proto2.proto](../../Helpers/wv_proto2.proto).
The dumper and regeneration helper do not extract or execute these archives.

## Included snapshots

| Repository archive | Original bundle | Retained contents |
| --- | --- | --- |
| [Dated protobuf sources](<WKS-KEYS (Version 2023-04-07)-protobuf-sources.zip>) | `WKS-KEYS (Version 2023-04-07).zip` | L1 and L3 proto2/proto3 schemas and generated modules; 8 files |
| [Updated protobuf sources](WKS-KEYS-protobuf-sources.zip) | `WKS-KEYS.zip` | L1 proto2/proto3 and L3 proto2/proto3/proto4 schemas and generated modules; 10 files |
| [L3 correction protobuf sources](WKS-KEYS_L3_correction-protobuf-sources.zip) | `WKS-KEYS_L3_correction.zip` | L3 proto2/proto3/proto4 schemas and generated modules; 6 files |

> 🧭 These are **repacked protobuf-only snapshots**, not byte-identical copies of
> the complete downloads. Each retained member keeps its original path and exact
> file bytes; ZIP metadata is normalized. Only `wv_proto*.proto` and
> `wv_proto*_pb2.py` files directly under `pywidevine/{L1,L3}/cdm/formats/` are
> included. The two later bundles also retain their original `WKS-KEYS/` path
> prefix.

The full `WKS-KEYS.zip` and `WKS-KEYS_L3_correction.zip` downloads contain
device-key, client-identity, and token files, described as placeholders by the
forum author. These snapshots exclude those files, cached bytecode, license
captures, and unrelated application files. The original downloads were left
untouched outside this repository.

All three snapshots contain the same L3 `wv_proto2.proto`, byte-identical to
`Helpers/wv_proto2.proto`. They also preserve the original `wv_proto2_pb2.py`
used before the runtime upgrade. The additional proto3/proto4 files are historical
references; they are not dependencies of this dumper's proto2 schema.

## Integrity and provenance

[SHA256SUMS](SHA256SUMS) records hashes of the repacked ZIPs stored here. From the
repository root, verify them with:

```sh
cd archives/wks-keys
shasum -a 256 -c SHA256SUMS
```

The original, complete downloads had these SHA-256 hashes. These identify the
input bundles and intentionally differ from the repacked archive hashes:

```text
f5a19fdfd4282358ec1e975c0fb8274708635b037e33bfca8a5c6fc7fa1d6691  WKS-KEYS (Version 2023-04-07).zip
77ed969017f5416feffef7ac4576d7426445d42c2aa968180e46678b34bc13cf  WKS-KEYS.zip
ccbb9efe57fc5a7f31a8a4e302728c9f5cc4a1edebf9fbe25f8a73e9fc65ac86  WKS-KEYS_L3_correction.zip
```

The schema used by this project was taken from the dated bundle's member:

```text
pywidevine/L3/cdm/formats/wv_proto2.proto
```

The original bundles were obtained from:

- [CrymanChen/WKS-KEYS GitHub releases](https://github.com/CrymanChen/WKS-KEYS/releases):
  `WKS-KEYS (Version 2023-04-07).zip`.
- [VideoHelp: WKS_KEYS updated protobuf to version 4](https://forum.videohelp.com/threads/411509-WKS_KEYS-updated-protobuf-to-version-4):
  `WKS-KEYS.zip` and `WKS-KEYS_L3_correction.zip`.

<details>
<summary>🧭 Additional regeneration background</summary>

- [Correcting Protobuf Downgrade to 3.19.0 error](https://forum.videohelp.com/threads/409040-Correcting-Protobuf-Downgrade-to-3-19-0-error)

</details>

To refresh these references, retain only the same schema/generated-module paths,
preserve their bytes, and update this inventory and `SHA256SUMS`. Keep the original
bundle names and hashes distinct from the repacked snapshot names and hashes.
