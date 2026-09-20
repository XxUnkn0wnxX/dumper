"""Small, per-run status messages for the experimental full-auto controller.

Normal CLI runs have no context and do not write status files. Messages contain
metadata and file digests only; captured key material stays in key_dumps/.
"""

import json
import os
from pathlib import Path
import re
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
MIN_ANDROID_API = 28
MAX_ANDROID_API = 33
ROLES = {'init', 'frida', 'dumper'}
_TOKEN = re.compile(r'[0-9a-f]{32}\Z')
_WRITE_LOCK = threading.Lock()
MAX_EVENT_BYTES = 1024 * 1024


class AutoSessionError(ValueError):
    """An automatic run cannot safely communicate its lifecycle state."""


def context():
    """Return the controller's directory/token/role, or None for manual runs."""
    directory = os.environ.get('DUMPER_AUTO_DIRECTORY')
    token = os.environ.get('DUMPER_AUTO_TOKEN', '')
    role = os.environ.get('DUMPER_AUTO_ROLE', '')
    if not directory and not token and not role:
        return None
    if not directory or not _TOKEN.fullmatch(token) or role not in ROLES:
        raise AutoSessionError('Invalid full-auto session context.')
    path = Path(directory)
    if path.is_symlink() or not path.is_dir() or path.resolve().parent != (ROOT / '.tmp').resolve():
        raise AutoSessionError('Full-auto status directory must be an owned directory under .tmp/.')
    return path, token, role


def marker_path(token):
    """Name one Android ownership record; never accept an arbitrary remote path."""
    if not _TOKEN.fullmatch(token):
        raise ValueError('Invalid full-auto session token.')
    return f'/data/local/tmp/.dumper-auto-{token}.pid'


def frida_marker():
    selected = context()
    if selected is None or selected[2] != 'frida':
        return None
    return marker_path(selected[1])


def emit_event(kind, **fields):
    """Append a complete status event without altering ordinary terminal output."""
    selected = context()
    if selected is None:
        return False
    directory, token, role = selected
    event = dict(fields, event=kind, token=token, role=role, pid=os.getpid(), time=time.time())
    data = (json.dumps(event, sort_keys=True) + '\n').encode('utf-8')
    target = directory / f'{role}.events.jsonl'
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        with _WRITE_LOCK:
            descriptor = os.open(target, flags, 0o600)
            try:
                remaining = memoryview(data)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError('incomplete status write')
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError as error:
        # A missing launch/completion event cannot be treated as a successful
        # handoff. The child must stop cleanly so its controller can clean up.
        raise AutoSessionError(f'Could not notify full_auto.py: {error}') from error
    return True


def read_events(directory, token, role):
    """Read only complete messages for this run; a partial final line can retry."""
    if not _TOKEN.fullmatch(token) or role not in ROLES:
        raise ValueError('Invalid full-auto event reader context.')
    path = Path(directory) / f'{role}.events.jsonl'
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
        raise ValueError('Invalid or oversized full-auto status file.')
    data = path.read_bytes()
    complete = data.rsplit(b'\n', 1)[0] if b'\n' in data else b''
    events = []
    for line in complete.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict) or event.get('token') != token or event.get('role') != role:
            raise ValueError('Full-auto status belongs to a different session.')
        events.append(event)
    return events
