"""Monitor the selected Frida transport and retained capture sessions."""

import threading
import time

import frida

# Notifications normally identify a disconnect immediately. A small read-only
# RPC also detects a stalled connection without launching ADB or reconnecting.
HEARTBEAT_INTERVAL = 5.0
HEARTBEAT_TIMEOUT = 2.0
FRIDA_CONNECTION_ERRORS = (
    frida.ServerNotRunningError,
    frida.TransportError,
    frida.TimedOutError,
    frida.PermissionDeniedError,
    frida.ProtocolError,
    frida.ProcessNotFoundError,
    frida.ProcessNotRespondingError,
    frida.InvalidOperationError,
    frida.NotSupportedError,
    frida.OperationCancelledError,
)


class CaptureDisconnected(RuntimeError):
    """Capture cannot continue on its original device and sessions."""


def _probe_agent(script, timeout=HEARTBEAT_TIMEOUT):
    """Bound RPC waits even on Frida versions whose RPC ignores cancellation.

    Native calls honor Cancellable, but some Python bindings wait indefinitely
    for an RPC reply after posting it. One daemon worker keeps that wait off the
    main thread. On timeout the caller stops capture and detaches the session;
    no further probe or reconnect is started.
    """
    complete = threading.Event()
    errors = []
    cancellable = frida.Cancellable()

    def query():
        try:
            with cancellable:
                script.list_exports_sync()
        except BaseException as error:
            errors.append(error)
        finally:
            complete.set()

    worker = threading.Thread(target=query, name='frida-capture-health', daemon=True)
    try:
        worker.start()
        if not complete.wait(timeout):
            raise frida.TimedOutError(f'capture agent did not respond within {timeout:g} seconds')
        if errors:
            raise errors[0]
    finally:
        cancellable.cancel()


class CaptureConnection:
    """Report connection loss on the main thread, never from Frida callbacks.

    Only successful capture sessions belong here. Temporary discovery and
    version-probe sessions intentionally detach and must not stop capture.
    """

    def __init__(self, usb_device, sessions, logger):
        self.device = usb_device
        self.sessions = tuple(sessions)
        self.logger = logger
        self._lock = threading.Lock()
        self._reason = None
        self._closed = False
        self._registrations = []
        self._next_heartbeat = time.monotonic() + HEARTBEAT_INTERVAL
        try:
            self._listen(self.device, 'lost', self._device_lost)
            for session, _script in self.sessions:
                self._listen(session, 'detached', self._session_detached)
            # Cover a disconnect that occurred during browser setup or before
            # listener registration: Frida retains these local state flags.
            self.check()
        except BaseException:
            self.close()
            raise

    # ----------------------------------------------------------------------
    # NOTIFICATIONS - latch the first reason and leave logging/exiting to run().
    # ----------------------------------------------------------------------
    def _listen(self, source, signal, callback):
        source.on(signal, callback)
        self._registrations.append((source, signal, callback))

    def _record(self, reason):
        with self._lock:
            if not self._closed and self._reason is None:
                self._reason = reason

    def _device_lost(self):
        self._record('Android device/ADB connection disconnected')

    def _session_detached(self, reason, crash=None):
        if reason in ('connection-terminated', 'device-lost'):
            self._record(f'Frida/device connection disconnected ({reason})')
        else:
            self._record(f'Capture session ended ({reason}); its hooks are no longer active')

    def _raise_if_disconnected(self):
        with self._lock:
            reason = self._reason
        if reason is not None:
            raise CaptureDisconnected(reason)

    # ----------------------------------------------------------------------
    # MAIN-THREAD CHECK - local flags each tick, bounded remote RPC every 5 s.
    # Listing exports checks the existing agent, without rerunning its hooks.
    # ----------------------------------------------------------------------
    def check(self, now=None):
        with self._lock:
            if self._closed:
                return
        self._raise_if_disconnected()
        if self.device.is_lost:
            self._device_lost()
        elif not self.sessions or any(session.is_detached for session, _ in self.sessions):
            self._record('Capture session disconnected; its hooks are no longer active')
        self._raise_if_disconnected()

        now = time.monotonic() if now is None else now
        if now < self._next_heartbeat:
            return
        self._next_heartbeat = now + HEARTBEAT_INTERVAL
        try:
            _probe_agent(self.sessions[0][1], timeout=HEARTBEAT_TIMEOUT)
        except FRIDA_CONNECTION_ERRORS + (frida.core.RPCException,) as error:
            self._record(f'Frida capture connection stopped responding: {error}')
        self._raise_if_disconnected()

    def close(self):
        """Remove callbacks before intentional session cleanup; safe to repeat."""
        with self._lock:
            self._closed = True
        registrations, self._registrations = self._registrations, []
        for source, signal, callback in reversed(registrations):
            try:
                source.off(signal, callback)
            except Exception as error:
                self.logger.debug('Could not remove Frida %s listener: %s', signal, error)
