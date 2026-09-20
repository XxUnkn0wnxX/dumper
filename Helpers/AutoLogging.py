"""Full-auto's fixed, unfiltered debug logs and single-run ownership lock."""

from contextlib import contextmanager
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading


LOG_NAMES = ('init.log', 'frida.log', 'dumper.log', 'full_auto.log')


def _open_log(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise OSError(f'Log path is not a regular file: {path}')
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f'Log path is not a regular file: {path}')
        os.ftruncate(descriptor, 0)
        os.chmod(path, 0o600)
        return os.fdopen(descriptor, 'w', encoding='utf-8', newline='')
    except BaseException:
        os.close(descriptor)
        raise


class _Tee:
    def __init__(self, terminal, log, lock):
        self.terminal = terminal
        self.log = log
        self.lock = lock

    def write(self, text):
        with self.lock:
            self.log.write(text)
            self.log.flush()
            return self.terminal.write(text)

    def flush(self):
        with self.lock:
            self.log.flush()
            self.terminal.flush()

    def write_bytes(self, value):
        with self.lock:
            self.log.flush()
            self.log.buffer.write(value)
            self.log.buffer.flush()
            buffer = getattr(self.terminal, 'buffer', None)
            if buffer is not None:
                buffer.write(value)
                buffer.flush()
            else:
                self.terminal.write(value.decode('utf-8', errors='replace'))

    def __getattr__(self, name):
        return getattr(self.terminal, name)


@contextmanager
def controller_logging(root: Path):
    """Lock one controller before overwriting logs; mirror its console output."""
    temporary = root / '.tmp'
    temporary.mkdir(exist_ok=True)
    # Keep the lock inode after exit: unlinking it could let a competing run
    # lock a replacement while another process still owns the old inode.
    lock_file = open(temporary / 'full-auto.lock', 'a+b')
    locked = False
    previous_flag = os.environ.get('DUMPER_AUTO_LOGGING')
    try:
        if os.name == 'nt':
            import msvcrt
            if lock_file.seek(0, os.SEEK_END) == 0:
                lock_file.write(b'0')
                lock_file.flush()
            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise OSError('Another full_auto.py run is active; its logs will not be overwritten.') from error
        else:
            import fcntl
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise OSError('Another full_auto.py run is active; its logs will not be overwritten.') from error
        locked = True
        logs = root / 'logs'
        if logs.is_symlink():
            raise OSError('logs/ must be a real directory, not a symbolic link.')
        logs.mkdir(exist_ok=True, mode=0o700)
        for name in LOG_NAMES[:-1]:
            with _open_log(logs / name):
                pass
        with _open_log(logs / 'full_auto.log') as log:
            original_out, original_err = sys.stdout, sys.stderr
            output_lock = threading.RLock()
            sys.stdout = _Tee(original_out, log, output_lock)
            sys.stderr = _Tee(original_err, log, output_lock)
            os.environ['DUMPER_AUTO_LOGGING'] = '1'
            try:
                yield logs
            finally:
                sys.stdout, sys.stderr = original_out, original_err
    finally:
        if previous_flag is None:
            os.environ.pop('DUMPER_AUTO_LOGGING', None)
        else:
            os.environ['DUMPER_AUTO_LOGGING'] = previous_flag
        if locked and os.name == 'nt':
            import msvcrt
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        lock_file.close()


def log_captured_output(result):
    """Include normally captured subprocess output in full-auto logs, uncut.

    The caller still receives its original result for parsing. Ordinary manual
    runs keep their existing terminal verbosity. Partial timeout output is also
    accepted because subprocess.TimeoutExpired exposes stdout/stderr.
    """
    if os.environ.get('DUMPER_AUTO_LOGGING') != '1' or getattr(result, '_auto_logged', False):
        return
    for name, stream in (('stdout', sys.stdout), ('stderr', sys.stderr)):
        value = getattr(result, name, None)
        if value:
            if isinstance(value, bytes):
                if isinstance(stream, _Tee):
                    stream.write_bytes(value)
                    continue
                buffer = getattr(stream, 'buffer', None)
                if buffer is not None:
                    buffer.write(value)
                    buffer.flush()
                    continue
                value = value.decode('utf-8', errors='replace')
            stream.write(value)
            stream.flush()


def run_logged_subprocess(command, **options):
    """Preserve captured command output even if cancellation interrupts parsing.

    During full auto, spool captured streams to disposable local files rather
    than pipes. A finally block emits all bytes the process wrote, including
    partial output from a cancelled or timed-out command. Normal runs retain
    subprocess.run's existing behavior and verbosity.
    """
    if os.environ.get('DUMPER_AUTO_LOGGING') != '1' or not options.get('capture_output'):
        return subprocess.run(command, **options)
    options = dict(options)
    options.pop('capture_output')
    scratch = Path(__file__).resolve().parents[1] / '.tmp'
    scratch.mkdir(exist_ok=True)
    result = None
    error = None
    with tempfile.TemporaryFile(dir=scratch) as out, tempfile.TemporaryFile(dir=scratch) as err:
        try:
            result = subprocess.run(command, stdout=out, stderr=err, **options)
        except BaseException as failure:
            error = failure
            raise
        finally:
            out.seek(0)
            err.seek(0)
            raw = subprocess.CompletedProcess(command, 0, out.read(), err.read())
            log_captured_output(raw)
            if error is not None:
                error._auto_logged = True
    if options.get('text') or options.get('universal_newlines') or options.get('encoding') or options.get('errors'):
        def decoded(value):
            return io.TextIOWrapper(
                io.BytesIO(value), encoding=io.text_encoding(options.get('encoding')),
                errors=options.get('errors') or 'strict', newline=None,
            ).read()
        result.stdout, result.stderr = decoded(raw.stdout), decoded(raw.stderr)
    else:
        result.stdout, result.stderr = raw.stdout, raw.stderr
    result._auto_logged = True
    return result
