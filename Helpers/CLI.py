"""Shared standard-library terminal and cancellation handling for the CLIs."""

from contextlib import contextmanager
import os
import signal
import sys


def _cancellation_signals():
    """Windows background process groups receive Ctrl+Break, not Ctrl+C."""
    signals = [signal.SIGINT]
    if hasattr(signal, 'SIGBREAK'):
        signals.append(signal.SIGBREAK)
    return signals


def prepare_terminal() -> None:
    """Repair interactive terminal flags left behind by an interrupted ADB shell.

    Raw mode can disable both newline-to-carriage-return mapping and Ctrl+C
    signals. Restore normal text input/output before the first setup operation.
    Pipes, redirected files, Windows consoles, and unavailable terminals are
    left alone. ADB may enter raw mode again after the later exec handoff.
    """
    if hasattr(signal, 'SIGBREAK'):
        # full_auto targets one new Windows process group with Ctrl+Break.
        # Translate it into the same KeyboardInterrupt cleanup path as Ctrl+C.
        try:
            signal.signal(signal.SIGBREAK, signal.default_int_handler)
        except (OSError, ValueError):
            pass
    if os.name != 'posix':
        return
    import termios

    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                continue
            descriptor = stream.fileno()
            attributes = termios.tcgetattr(descriptor)
            # Keep baud rate, character size, and other unrelated preferences.
            attributes[0] &= ~(termios.IGNCR | termios.INLCR)
            attributes[0] |= termios.ICRNL
            attributes[1] |= termios.OPOST | termios.ONLCR
            attributes[1] &= ~(termios.OCRNL | termios.ONLRET | termios.ONOCR)
            attributes[3] |= termios.ISIG | termios.ICANON | termios.ECHO
            attributes[6][termios.VINTR] = b'\x03'
            termios.tcsetattr(descriptor, termios.TCSANOW, attributes)
        except (AttributeError, OSError, TypeError, ValueError, termios.error):
            # Captured test streams and detached terminals need no repair.
            continue


@contextmanager
def defer_interrupts():
    """Finish a short cleanup, then deliver its first Ctrl+C to the caller.

    Normal discovery and temporary-file cleanup can be followed by more work.
    They must remember a cancellation instead of silently continuing afterward.
    An outer shutdown guard that already ignores SIGINT takes precedence.
    """
    interrupted = False

    def remember_interrupt(_signal, _frame):
        nonlocal interrupted
        interrupted = True

    installed = []
    for signum in _cancellation_signals():
        try:
            previous = signal.getsignal(signum)
            if previous != signal.SIG_IGN:
                signal.signal(signum, remember_interrupt)
                installed.append((signum, previous))
        except (OSError, ValueError):
            pass
    cleanup_failed = False
    try:
        yield
    except BaseException:
        cleanup_failed = True
        raise
    finally:
        for signum, previous in reversed(installed):
            signal.signal(signum, previous)
        # A caller may be handling a recoverable failure and retrying next.
        # Only an exception from this cleanup body takes precedence; an
        # ambient handled exception must not hide the user's cancellation.
        if interrupted and not cleanup_failed:
            raise KeyboardInterrupt


@contextmanager
def ignore_interrupts():
    """Protect short, bounded cleanup from a second Ctrl+C, then restore it.

    Use only while unwinding cancelled work or restoring output files, never
    around normal device, network, compiler, or capture operations.
    """
    installed = []
    for signum in _cancellation_signals():
        try:
            previous = signal.signal(signum, signal.SIG_IGN)
            installed.append((signum, previous))
        except (OSError, ValueError):
            # Signal handlers can only be changed from Python's main thread.
            pass
    try:
        yield
    finally:
        for signum, previous in reversed(installed):
            signal.signal(signum, previous)
