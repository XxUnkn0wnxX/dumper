# ------------------------------------------------------------------------------
# DEVICE BRIDGE
# Select the Android target, load Helpers/script.js through Frida, and process
# the agent's messages. Python matches captured keys to client IDs and saves pairs.
# ------------------------------------------------------------------------------
import os
import logging
import base64
import frida
from Crypto.PublicKey import RSA
# Generated bindings decode the captured license request. Edit wv_proto2.proto
# and run tools/regenerate_protobuf.py to rebuild them; see Helpers/README.md.
from Helpers.wv_proto2_pb2 import SignedLicenseRequest
from Helpers.DeviceSelection import select_android_device


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
        self.widevine_libraries = module_names
        self.usb_device = select_android_device(device_id)
        self.name = self.usb_device.name

        with open('./Helpers/script.js', 'r', encoding="utf_8") as script:
            self.frida_script = script.read()
        self.frida_script = self.frida_script.replace(r'${DYNAMIC_FUNCTION_NAME}', dynamic_function_name)
        self.frida_script = self.frida_script.replace(r'${CDM_VERSION}', cdm_version)

    # --------------------------------------------------------------------------
    # PAIR OUTPUT
    # Called after license_request_message finds a matching cached private key.
    # Group output by device, certificate system ID, and decimal modulus prefix.
    # --------------------------------------------------------------------------
    def export_key(self, key, client_id):
        save_dir = os.path.join(
            'key_dumps',
            f'{self.name}',
            'private_keys',
            f'{client_id.Token._DeviceCertificate.SystemId}',
            f'{str(key.n)[:10]}'
        )

        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        with open(os.path.join(save_dir, 'client_id.bin'), 'wb+') as writer:
            writer.write(client_id.SerializeToString())

        with open(os.path.join(save_dir, 'private_key.pem'), 'wb+') as writer:
            writer.write(key.exportKey('PEM'))
        self.logger.info('Key pairs saved at %s', save_dir)

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
        script = process.create_script(self.frida_script)
        script.load()
        loaded_modules = []
        try:
            for lib in self.widevine_libraries:
                try:
                    loaded_modules.append(script.exports.getmodulebyname(lib))
                except frida.core.RPCException as e:
                    # Hide the cases where the module cannot be found
                    continue
                except Exception as e:
                    raise(e)
        finally:
            # End the discovery attachment and return the matches collected so far.
            # This return also suppresses pending exceptions from the query loop.
            process.detach()
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
