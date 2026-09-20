# 🧰 Maintainer tools

[← Back to the Dumper README](../README.md)

The detailed maintainer documentation moved to dedicated guides so each tool
has one owner:

| Tool or topic | Guide |
| --- | --- |
| Android image, ADB, root, and authorization | [Android setup](../docs/android-setup.md) |
| `setup_frida.py` installation, shell mode, cache, arguments, cleanup, and Ctrl+C | [Frida server setup](../docs/frida-setup.md) |
| `regenerate_protobuf.py`, schema, runtime pin, and provenance | [Protobuf guide](../docs/protobuf.md) |
| `generate_wvd.py`, pair validation, and WVD replacement | [WVD generation](../docs/wvd.md) |
| Experimental background controller | [Full-auto workflow](../docs/full-auto.md) |
| Regression commands and verified scope | [Testing guide](../docs/testing.md) |

Run `python3 init.py` first on initial setup (`py -3 init.py` on Windows), from
the repository root. Both scripts also provide a fallback: they
[initialize `.venv` automatically](../docs/setup.md#automatic-environment-setup)
when launched outside any venv, or use an already active venv as-is. The Frida
helper also synchronizes the host Frida package with the selected Android server
inside that environment. Initialization installs the root requirements,
including the bundled `adbutils` fallback on supported hosts; the helper still prefers a global
`adb` on `PATH`.

The source files remain beside this pointer:

- [`setup_frida.py`](setup_frida.py)
- [`regenerate_protobuf.py`](regenerate_protobuf.py)
