# 📝 Future SDK and helper TODO

[← Back to the Dumper README](../README.md) · [🧪 Current evidence](testing.md) · [🧩 Dumper layout guide](dumper.md)

Planned work for newer Android SDK images. Android 14–17 support is currently
unverified. WVD generation is documented in the [WVD guide](wvd.md).

## Android 14–17 SDK and Widevine inventory

- [ ] Inventory downloaded Android 14–17 images, recording their API level,
  build, ABI, and root availability. Read images from a configurable local SDK root.
- [ ] Extract the relevant Widevine `.so` modules and record their SDK package,
  revision, and SHA-256 hashes.
- [ ] Compare exports and complete `PrepareKeyRequest` signatures for each
  relevant module, recording the output argument position only when the
  signature has been verified.
- [ ] Add the inspected signatures and their source metadata to the fixtures;
  update detection only where the module evidence supports a new layout.
