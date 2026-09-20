# 📦 Optional WVD tooling

[← Back to the Dumper README](../README.md) · [🧱 Python setup](setup.md) · [🧬 Protobuf guide](protobuf.md)

[`requirements-wvd.txt`](../requirements-wvd.txt) provides
[`pywidevine`](https://pypi.org/project/pywidevine/) for future work with
Widevine device (`.wvd`) files. This is optional preparation; the dumper
currently writes `client_id.bin` and `private_key.pem`, and automatic WVD
creation is not implemented.

> [!IMPORTANT]
> **Use a separate virtual environment.** `pywidevine` 1.9.0 requires
> `protobuf>=6.33.0,<7.0.0`, while the dumper's shipped binding requires
> `protobuf==7.36.2`. Do not install both requirements files into one
> environment or bypass dependency checks with `--no-deps`.

| Purpose | Environment | Requirements |
| --- | --- | --- |
| Run the dumper or regenerate its binding | `.venv` | [`requirements.txt`](../requirements.txt) |
| Use `pywidevine` for WVD work | `.venv-wvd` | [`requirements-wvd.txt`](../requirements-wvd.txt) |

From the repository root, create the optional environment with Python 3.10 or
newer and install only its requirements:

```sh
python3 -m venv .venv-wvd
.venv-wvd/bin/python -m pip install --upgrade -r requirements-wvd.txt
.venv-wvd/bin/python -m pip check
.venv-wvd/bin/pywidevine --help
```

In Windows PowerShell:

```powershell
py -3 -m venv .venv-wvd
.venv-wvd\Scripts\python.exe -m pip install --upgrade -r requirements-wvd.txt
.venv-wvd\Scripts\python.exe -m pip check
.venv-wvd\Scripts\pywidevine.exe --help
```

These commands use each environment directly, so activation is optional. Run
the dumper with `.venv/bin/python` and WVD tooling with `.venv-wvd/bin/python`
or `.venv-wvd/bin/pywidevine` (the corresponding `Scripts` paths on Windows).
The optional requirement is unpinned so pip can resolve compatible releases
within that environment. `.venv-wvd/` is ignored by Git.
