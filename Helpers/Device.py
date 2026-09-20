# ------------------------------------------------------------------------------
# DEVICE BRIDGE
# Select the Android target, load Helpers/script.js through Frida, and process
# the agent's messages. Python matches captured keys to client IDs and saves pairs.
# ------------------------------------------------------------------------------
import os
import logging
import base64
import re
import stat
from datetime import datetime, timedelta

import frida
from Crypto.PublicKey import RSA
# Generated bindings decode the captured license request. Edit wv_proto2.proto
# and run tools/regenerate_protobuf.py to rebuild them; see Helpers/README.md.
from Helpers.wv_proto2_pb2 import SignedLicenseRequest
from Helpers.DeviceSelection import get_android_api_level, select_android_device


# ------------------------------------------------------------------------------
# OUTPUT PATH POLICY
# Keep the production root relative to the checkout (and ignored by Git). The
# component sanitizer protects platform-specific path rules while retaining
# ordinary names, spaces, and version dots.
# ------------------------------------------------------------------------------
KEY_DUMPS_ROOT = 'key_dumps'
_MAX_PATH_COMPONENT_LENGTH = 120
_INVALID_PATH_CHARACTERS = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')
_WINDOWS_RESERVED_NAMES = {
    'CON', 'PRN', 'AUX', 'NUL',
    *(f'COM{number}' for number in range(1, 10)),
    *(f'LPT{number}' for number in range(1, 10)),
}


def _safe_path_component(value, fallback='unknown', *, byte_limit=_MAX_PATH_COMPONENT_LENGTH):
    """Make one dynamic output-directory component safe on major host OSes."""
    component = str(value) if value is not None else ''
    # Replace malformed Unicode before filtering: UTF-8 replacement can itself
    # produce a question mark, which also needs removal for Windows filenames.
    component = component.encode('utf-8', errors='replace').decode('utf-8')
    component = _INVALID_PATH_CHARACTERS.sub('_', component)
    component = component.rstrip(' .')
    if not component or component in {'.', '..'}:
        component = fallback

    reserved_name = component.split('.', 1)[0].rstrip(' .').upper()
    if reserved_name in _WINDOWS_RESERVED_NAMES:
        component = f'_{component}'

    component_bytes = component.encode('utf-8')[:byte_limit]
    component = component_bytes.decode('utf-8', errors='ignore').rstrip(' .')
    return component or fallback


def _ensure_directory(path):
    """Create one output directory without traversing a pre-existing symlink."""
    path = os.path.abspath(os.fspath(path))
    if os.path.lexists(path):
        if os.path.islink(path):
            raise OSError(f'output path is a symlink: {path}')
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise OSError(f'output path is not a directory: {path}')
        return

    try:
        os.mkdir(path)
    except FileExistsError:
        # Another writer may have won the race. Re-check its type rather than
        # following a newly-created symlink.
        if os.path.islink(path):
            raise OSError(f'output path is a symlink: {path}')
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise OSError(f'output path is not a directory: {path}')


def _claim_directory(parent, name):
    """Claim a child directory exclusively, returning False when it exists."""
    path = os.path.join(parent, name)
    try:
        os.mkdir(path)
    except FileExistsError:
        return False
    return path


def _allocate_output_directory(parent, base_name, logger):
    """Allocate the base path or a local timestamp sibling without overwriting."""
    claimed = _claim_directory(parent, base_name)
    if claimed:
        return claimed

    logger.warning(
        'Preserving existing key output directory %s; allocating a timestamped sibling',
        os.path.join(parent, base_name),
    )
    timestamp = datetime.now()
    for attempt in range(1000):
        if attempt == 0:
            timestamp_label = timestamp.strftime('%Y-%m-%d %H-%M-%S')
        else:
            timestamp_label = (timestamp + timedelta(microseconds=attempt)).strftime(
                '%Y-%m-%d %H-%M-%S.%f'
            )
        candidate_name = f'{base_name} ({timestamp_label})'
        candidate = _claim_directory(parent, candidate_name)
        if candidate:
            return candidate
        if os.path.islink(os.path.join(parent, candidate_name)):
            logger.warning('Skipping pre-existing symlink at %s', os.path.join(parent, candidate_name))

    raise OSError(f'could not allocate a unique output directory for {base_name!r}')


def _write_exclusive(path, payload):
    """Write bytes to a new regular file without following or replacing links."""
    # The Windows CRT otherwise translates newlines in these binary payloads.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0)
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(f'could not write output file {path}')
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_regular_file(path, expected_length=None):
    """Read a regular output file while rejecting pre-existing symlinks."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            chunks = []
            total = 0
            while expected_length is None or total <= expected_length:
                read_size = 1024 * 1024
                if expected_length is not None:
                    read_size = min(read_size, expected_length + 1 - total)
                chunk = os.read(descriptor, read_size)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if expected_length is not None and total > expected_length:
                    return None
            return b''.join(chunks)
        finally:
            os.close(descriptor)
    except (FileNotFoundError, OSError):
        return None


def _pair_matches(path, client_id_bytes, private_key_bytes):
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return False
    except (FileNotFoundError, OSError):
        return False
    return (
        _read_regular_file(
            os.path.join(path, 'client_id.bin'), len(client_id_bytes)
        ) == client_id_bytes
        and _read_regular_file(
            os.path.join(path, 'private_key.pem'), len(private_key_bytes)
        ) == private_key_bytes
    )


# ------------------------------------------------------------------------------
# HOOK ERRORS - give the CLI process/library context when initialization fails.
# ------------------------------------------------------------------------------
class HookError(RuntimeError):
    """Raised when a Frida library hook cannot be installed."""


class Device:
    # --------------------------------------------------------------------------
    # TARGET AND AGENT SETUP
    # Verify Android before scanning processes; prepare the JavaScript with the
    # CLI settings. Signature matching itself runs inside the JavaScript agent.
    # --------------------------------------------------------------------------
    def __init__(self, dynamic_function_name, cdm_version, module_names, device_id=None):
        self.logger = logging.getLogger(__name__)
        # Index captured private keys by RSA modulus for later certificate matching.
        self.saved_keys = {}
        self._saved_pair_paths = {}
        self.widevine_libraries = module_names
        self.usb_device = select_android_device(device_id)
        self.name = self.usb_device.name
        # This is intentionally independent from the --cdm-version layout
        # setting, which controls only the Frida hook argument layout.
        self.android_api_level = get_android_api_level(self.usb_device)

        with open('./Helpers/script.js', 'r', encoding="utf_8") as script:
            self.frida_script = script.read()
        self.frida_script = self.frida_script.replace(r'${DYNAMIC_FUNCTION_NAME}', dynamic_function_name)
        self.frida_script = self.frida_script.replace(r'${CDM_VERSION}', cdm_version)

    # --------------------------------------------------------------------------
    # PAIR OUTPUT
    # Called after license_request_message finds a matching cached private key.
    # Group output by device, the CDM version embedded in ClientInfo, and API.
    # --------------------------------------------------------------------------
    def export_key(self, key, client_id):
        client_id_bytes = client_id.SerializeToString()
        client_id_bytes = bytes(client_id_bytes)
        private_key_bytes = bytes(key.export_key(format='PEM'))

        pair_key = (client_id_bytes, private_key_bytes)
        saved_pair_paths = getattr(self, '_saved_pair_paths', None)
        if saved_pair_paths is None:
            saved_pair_paths = self._saved_pair_paths = {}
        cached_path = saved_pair_paths.get(pair_key)
        if cached_path and _pair_matches(cached_path, client_id_bytes, private_key_bytes):
            self.logger.info('Key pair already saved at %s', cached_path)
            return cached_path
        if cached_path:
            saved_pair_paths.pop(pair_key, None)

        cdm_version = self._client_cdm_version(client_id)
        device_component = _safe_path_component(self.name)
        # Budget each value separately so truncating long metadata never removes
        # the API label. Leave room for the timestamp suffix on all host systems.
        cdm_component = _safe_path_component(cdm_version, byte_limit=80)
        api_component = _safe_path_component(
            getattr(self, 'android_api_level', 'unknown'), byte_limit=24,
        )
        base_name = f'CDM {cdm_component} - API {api_component}'
        root = os.path.abspath(os.fspath(KEY_DUMPS_ROOT))
        device_root = os.path.join(root, device_component)
        save_parent = os.path.join(device_root, 'private_keys')
        try:
            _ensure_directory(root)
            _ensure_directory(device_root)
            _ensure_directory(save_parent)
            save_dir = _allocate_output_directory(save_parent, base_name, self.logger)
            _write_exclusive(os.path.join(save_dir, 'client_id.bin'), client_id_bytes)
            _write_exclusive(os.path.join(save_dir, 'private_key.pem'), private_key_bytes)
        except (OSError, ValueError) as error:
            self.logger.warning('Could not save key pair under %s: %s', save_parent, error)
            return None

        if not _pair_matches(save_dir, client_id_bytes, private_key_bytes):
            self.logger.warning('Key pair verification failed at %s', save_dir)
            return None
        saved_pair_paths[pair_key] = save_dir
        self.logger.info('Key pairs saved at %s', save_dir)
        return save_dir

    def _client_cdm_version(self, client_id):
        """Read one unambiguous CDM version from the client metadata."""
        try:
            values = [
                entry.Value
                for entry in client_id.ClientInfo
                if entry.Name == 'widevine_cdm_version'
            ]
        except (AttributeError, TypeError):
            values = []

        if not values or any(not isinstance(value, str) or not value.strip() for value in values):
            self.logger.warning(
                'Client ID has missing or blank widevine_cdm_version metadata; using unknown label'
            )
            return 'unknown'
        if len(set(values)) != 1:
            self.logger.warning(
                'Client ID has conflicting widevine_cdm_version metadata; using unknown label'
            )
            return 'unknown'
        return values[0]

    # --------------------------------------------------------------------------
    # AGENT MESSAGE DISPATCH - payload names must agree with Helpers/script.js.
    # private_key carries DER key bytes; device_info carries a license request;
    # message_info carries UTF-8 status text. Frida supplies bytes through data.
    # --------------------------------------------------------------------------
    def on_message(self, msg, data):
        if 'payload' in msg:
            if msg['payload'] == 'private_key':
                key = RSA.import_key(data)
                if key.n not in self.saved_keys:
                    self.logger.debug(
                        'Retrieved key: \n\n%s\n',
                        key.export_key().decode("utf-8")
                    )
                self.saved_keys[key.n] = key
            elif msg['payload'] == 'device_info':
                self.license_request_message(data)
            elif msg['payload'] == 'message_info':
                self.logger.info(data.decode())

    # --------------------------------------------------------------------------
    # CLIENT ID AND KEY MATCHING
    # Parse the request's device certificate and use its public-key modulus to
    # select a captured private key. A request alone does not create output files.
    # --------------------------------------------------------------------------
    def license_request_message(self, data):
        self.logger.debug(
            'Retrieved build info: \n\n%s\n',
            base64.b64encode(data).decode('utf-8')
        )
        root = SignedLicenseRequest()
        root.ParseFromString(data)
        public_key = root.Msg.ClientId.Token._DeviceCertificate.PublicKey
        key = RSA.importKey(public_key)
        cur = self.saved_keys.get(key.n)

        # The key must already be cached when this request arrives. Requests are
        # not queued for retry if their corresponding private key arrives later.
        if cur is not None:
            self.export_key(cur, root.Msg.ClientId)

    # --------------------------------------------------------------------------
    # LIBRARY DISCOVERY
    # Use a temporary attachment to query the requested module names through the
    # agent. This RPC only locates modules; hook_to_process installs capture hooks.
    # --------------------------------------------------------------------------
    def find_widevine_process(self, process_name):
        process = self.usb_device.attach(process_name)
        loaded_modules = []
        try:
            script = process.create_script(self.frida_script)
            script.load()
            for lib in self.widevine_libraries:
                try:
                    loaded_modules.append(script.exports.getmodulebyname(lib))
                except frida.core.RPCException as e:
                    # Hide the cases where the module cannot be found
                    continue
                except Exception as e:
                    raise(e)
        finally:
            # End the discovery attachment even when setup or module lookup is
            # interrupted. Cleanup errors must not replace the original failure.
            try:
                process.detach()
            except Exception as detach_error:
                self.logger.warning(
                    'Failed to detach discovery session for process %s: %s',
                    process_name,
                    detach_error,
                )
        return loaded_modules

    # --------------------------------------------------------------------------
    # CAPTURE SESSION LIFECYCLE
    # Register the message handler before loading and initializing the agent.
    # Successful sessions stay attached; initialization failures become HookError.
    # --------------------------------------------------------------------------
    def hook_to_process(self, process, library):
        session = None
        try:
            session = self.usb_device.attach(process)
            script = session.create_script(self.frida_script)
            script.on('message', self.on_message)
            script.load()
            script.exports.hooklibfunctions(library)
            return session
        except Exception as error:
            # Detach a partially initialized session without replacing the original
            # hook error if cleanup itself fails.
            if session is not None:
                try:
                    session.detach()
                except Exception as detach_error:
                    self.logger.warning(
                        'Failed to detach unsuccessful hook session for process %s: %s',
                        process,
                        detach_error,
                    )
            raise HookError(
                f'Failed to hook library {library!r} in process {process!r}: {error}'
            ) from error
