/*
 * FRIDA AGENT
 * Helpers/Device.py fills in the configuration below and loads this script into
 * the Android process. Captured data and status messages return to Python via send().
 *
 * For automatic layout support, see AUTO-DETECTION SIGNATURES and LAYOUT SELECTION.
 */

/* --------------------------------------------------------------------------
 * CONFIGURATION - supplied by the Python CLI before the agent is loaded.
 * -------------------------------------------------------------------------- */
const DYNAMIC_FUNCTION_NAME = '${DYNAMIC_FUNCTION_NAME}';
const CDM_VERSION = '${CDM_VERSION}';

/* --------------------------------------------------------------------------
 * KNOWN PRIVATE-KEY FUNCTION NAMES
 * Used to suggest likely names after discovery. With no explicit function name,
 * hookLibFunctions scans all lowercase function exports, not only this list.
 * These names are independent of the PrepareKeyRequest signatures below.
 * -------------------------------------------------------------------------- */
const KNOWN_DYNAMIC_FUNCTION_NAMES = [
    'rnmsglvj',
    'polorucp',
    'kqzqahjq',
    'pldrclfq',
    'kgaitijd',
    'dnvffnze',
    'cwkfcplc',
    'crhqcdet',
    'igrqajte',
    'ofskesua',
    'ppsniaij',
    'qkfrcjtw',
    'zrtoooke',
    'rbhjspoh',
    'gndskkuk',
    'wzpmjqna',
    'faokrmio',
    'uerbupkh',
    'ygjiljer',
    'dirwetvo',
    'sxxprljw'
];

/* --------------------------------------------------------------------------
 * MESSAGE ENCODING
 * UTF-8 encoder used for status messages sent to Python in the Frida runtime.
 * Adapted from https://gist.github.com/Yaffle/5458286#file-textencodertextdecoder-js
 * -------------------------------------------------------------------------- */
function TextEncoder() {
}

/* Convert text to UTF-8 bytes for message_info payloads; Python decodes them as UTF-8. */
TextEncoder.prototype.encode = function (string) {
    var octets = [];
    var length = string.length;
    var i = 0;
    while (i < length) {
        /* Choose the UTF-8 sequence length for this Unicode code point. */
        var codePoint = string.codePointAt(i);
        var c = 0;
        var bits = 0;
        if (codePoint <= 0x0000007F) {
            c = 0;
            bits = 0x00;
        } else if (codePoint <= 0x000007FF) {
            c = 6;
            bits = 0xC0;
        } else if (codePoint <= 0x0000FFFF) {
            c = 12;
            bits = 0xE0;
        } else if (codePoint <= 0x001FFFFF) {
            c = 18;
            bits = 0xF0;
        }
        /* Emit the leading byte, then any required continuation bytes. */
        octets.push(bits | (codePoint >> c));
        c -= 6;
        while (c >= 0) {
            octets.push(0x80 | ((codePoint >> c) & 0x3F));
            c -= 6;
        }
        /* JavaScript stores supplementary code points as two UTF-16 code units. */
        i += codePoint >= 0x10000 ? 2 : 1;
    }
    return octets;
}

/* --------------------------------------------------------------------------
 * PRIVATE-KEY CAPTURE
 * Inspect candidate function arguments for an encoded RSA key and send it to
 * Python. The request layout table below does not control this hook's arguments.
 * -------------------------------------------------------------------------- */
function getPrivateKey(address) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            /* Candidate functions are inspected using args[5] as the buffer and
             * args[6] as its length. These checks filter likely RSA key buffers.
             */
            if (!args[6].isNull()) {
                const size = args[6].toInt32();
                if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                    const buf = args[5].readByteArray(size);
                    const bytes = new Uint8Array(buf);
                    // The first two bytes of the DER encoding are 0x30 and 0x82 (MII).
                    if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                        try {
                            /* DER records its own length. Trim trailing buffer data
                             * before sending the key bytes to Device.on_message().
                             */
                            const binaryString = a2bs(bytes)
                            const keyLength = getKeyLength(binaryString);
                            const key = bytes.slice(0, keyLength);
                            send('private_key', key);
                        } catch (error) {
                            console.log(error)
                        }
                    }
                }
            }
        }
    });
}

/* --------------------------------------------------------------------------
 * PRIVACY MODE
 * Force UsePrivacyMode to return false so the captured request exposes the client
 * identification instead of encrypting it with the license server's public key.
 * -------------------------------------------------------------------------- */
function disablePrivacyMode(address) {
    Interceptor.attach(address, {
        onLeave: function (retval) {
            retval.replace(ptr(0));
        }
    });
}

/* ==========================================================================
 * AUTO-DETECTION SIGNATURES - add verified PrepareKeyRequest layouts here.
 *
 * Each key is the COMPLETE exported C++ symbol name, matched exactly at runtime.
 * argumentIndex selects the first output string pointer in Frida's args array.
 * versions lists equivalent manual CLI labels for logging; it does not identify
 * the installed plugin version. Android/API versions never drive this lookup.
 *
 * When adding a signature:
 * 1. Verify the exported symbol and argument layout from the actual library.
 *    Keep exact matching; do not infer the layout from a name fragment or OS version.
 * 2. Record the symbol, package/revision, library hash, pointer size, and expected
 *    argumentIndex in tests/fixtures/cdm_signatures.json. That file is test data;
 *    this table is the runtime source of supported signatures.
 * 3. Run node tests/test_cdm_detection.js, then verify on the target device.
 *    Existing SDK evidence is offline and does not prove live compatibility.
 * ========================================================================== */
const PREPARE_KEY_REQUEST_LAYOUTS = {
    /*
     * Layout: first output at args[4]. Observed in Android 9-11 SDK samples.
     * Inputs: InitializationData, license type, map; then output string pointers.
     */
    '_ZN5wvcdm10CdmLicense17PrepareKeyRequestERKNS_18InitializationDataENS_14CdmLicenseTypeERKNSt3__13mapINS5_12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEESC_NS5_4lessISC_EENSA_INS5_4pairIKSC_SC_EEEEEEPSC_SM_': {
        argumentIndex: 4,
        versions: '14.0.0 / 15.0.0 / 16.0.0'
    },
    /*
     * Layout: first output at args[5]. Observed in Android 12, 12L, and 13 samples.
     * An extra string input after InitializationData shifts the output pointers.
     */
    '_ZN5wvcdm10CdmLicense17PrepareKeyRequestERKNS_18InitializationDataERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEENS_14CdmLicenseTypeERKNS4_3mapISA_SA_NS4_4lessISA_EENS8_INS4_4pairISB_SA_EEEEEEPSA_SN_': {
        argumentIndex: 5,
        versions: '16.1.0 / 17.0.0'
    }
};

/* --------------------------------------------------------------------------
 * LAYOUT SELECTION - validate exports before installing any hooks.
 * Both modes require exactly one exported PrepareKeyRequest function. Auto mode
 * also requires an exact signature match; manual mode uses the selected CLI label.
 * Missing, ambiguous, or unrecognized auto signatures abort this library's setup.
 * -------------------------------------------------------------------------- */
function selectPrepareKeyRequest(entries, libraryName) {
    const candidates = entries.filter(entry =>
        entry.type === 'function' && entry.name.includes('PrepareKeyRequest'));
    if (candidates.length !== 1) {
        throw new Error('Expected one exported PrepareKeyRequest function in ' + libraryName +
            ', found ' + candidates.length + '. Check --module-name and library compatibility.');
    }

    const entry = candidates[0];
    let layout;
    if (CDM_VERSION === 'auto') {
        if (!Object.prototype.hasOwnProperty.call(PREPARE_KEY_REQUEST_LAYOUTS, entry.name)) {
            throw new Error('Cannot auto-detect the PrepareKeyRequest layout in ' + libraryName +
                ': unrecognized signature ' + entry.name +
                '. Supply --cdm-version only if you know the correct supported layout for this library.');
        }
        /* Exact symbol lookup selects the output argument without probing memory. */
        layout = PREPARE_KEY_REQUEST_LAYOUTS[entry.name];
        send('message_info', new TextEncoder().encode(
            'Auto-detected PrepareKeyRequest layout in ' + libraryName + ': args[' +
            layout.argumentIndex + '] (CDM settings ' + layout.versions + ').'));
    } else {
        /* Manual overrides bypass signature matching, but keep the single-function check.
         * If adding CLI labels, also update dump_keys.py choices and CLI regressions.
         */
        const manualLayouts = {
            '14.0.0': 4, '15.0.0': 4, '16.0.0': 4,
            '16.1.0': 5, '17.0.0': 5
        };
        if (!Object.prototype.hasOwnProperty.call(manualLayouts, CDM_VERSION)) {
            throw new Error('Unsupported --cdm-version: ' + CDM_VERSION);
        }
        layout = { argumentIndex: manualLayouts[CDM_VERSION] };
        send('message_info', new TextEncoder().encode(
            'Using manual CDM setting ' + CDM_VERSION + ' in ' + libraryName +
            ': PrepareKeyRequest args[' + layout.argumentIndex + '].'));
    }
    return { entry: entry, argumentIndex: layout.argumentIndex };
}

/* --------------------------------------------------------------------------
 * LICENSE-REQUEST CAPTURE
 * Save the selected output pointer on entry, then read the populated string on
 * return. Python extracts the client ID and matches it with the captured key.
 * -------------------------------------------------------------------------- */
function prepareKeyRequest(address, argumentIndex) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.ret = args[argumentIndex];
        },
        onLeave: function () {
            if (this.ret) {
                /* Read the length and data pointer using the existing C++ string
                 * layout. Process.pointerSize adjusts the offsets for 32/64-bit.
                 * A new ABI may require changes here as well as a signature entry.
                 */
                const size = ptr(this.ret).add(Process.pointerSize).readU32();
                const arr = this.ret.add(Process.pointerSize * 2).readPointer().readByteArray(size);
                send('device_info', arr);
            }
        }
    });
}

/* --------------------------------------------------------------------------
 * HOOK SETUP - called by Python for each candidate library.
 * Resolve the request layout first, attach only function exports, and report the
 * attachment count. A failed request hook prevents a successful initialization.
 * -------------------------------------------------------------------------- */
function hookLibFunctions(lib) {
    const name = lib['name'];
    const baseAddr = lib['base'];
    let message = 'Hooking ' + name + ' at ' + baseAddr;
    let hookedProvidedModule = false;
    let funcNames = [];
    let successfulHookCount = 0;
    let requestHooked = false;

    send('message_info', new TextEncoder().encode(message));

    const mod = Process.getModuleByName(name);
    const entries = mod.enumerateExports();
    // Resolve the layout before installing any hooks. Never probe argument
    // pointers to guess the layout during playback.
    const request = selectPrepareKeyRequest(entries, name);

    /* Dispatch function exports to the privacy, request, or private-key hook.
     * An explicit private-key name uses substring matching; otherwise all lowercase
     * names are candidates. Data exports must never reach Interceptor.attach().
     */
    entries.forEach(function (module) {
        if (module.type !== 'function') {
            return;
        }
        try {
            let hookedModule;
            if (module.name.includes('UsePrivacyMode')) {
                disablePrivacyMode(module.address);
                hookedModule = module.name;
            } else if (module.name === request.entry.name) {
                prepareKeyRequest(module.address, request.argumentIndex);
                requestHooked = true;
                hookedModule = module.name;
            } else if (DYNAMIC_FUNCTION_NAME !== '' && module.name.includes(DYNAMIC_FUNCTION_NAME)) {
                getPrivateKey(module.address);
                hookedModule = module.name;
                hookedProvidedModule = true;
            } else if (DYNAMIC_FUNCTION_NAME === '' && module.name.match(/^[a-z]+$/)) {
                getPrivateKey(module.address);
                hookedModule = module.name;
                funcNames.push(hookedModule);
            }

            /* Count and report only attachments that returned without throwing. */
            if (hookedModule) {
                successfulHookCount += 1;
                const message = 'Hooked ' + hookedModule + ' at ' + module.address;
                send('message_info', new TextEncoder().encode(message));
            }
        } catch (e) {
            /* Continue inspecting other exports; required-hook checks follow below. */
            console.log("Error: " + e + " at F: " + module.name);
        }
    });

    /* Report an explicit name that did not attach, or suggest known names among
     * successfully hooked candidates. Suggestions do not prove a key was captured.
     */
    if (DYNAMIC_FUNCTION_NAME !== '' && !hookedProvidedModule) {
        const message = "Unable to find '" + DYNAMIC_FUNCTION_NAME + "'";
        send('message_info', new TextEncoder().encode(message));
    }

    if (DYNAMIC_FUNCTION_NAME === '') {
        const possibleFuncNames = KNOWN_DYNAMIC_FUNCTION_NAMES.filter(x => funcNames.includes(x));
        if (possibleFuncNames.length) {
            message = "Your function name is most likely: " + "'" + possibleFuncNames.join('\', \'') + "'";
            send('message_info', new TextEncoder().encode(message));
        }
    }

    /* Hook installation is successful only if the request hook attached.
     * Python saves a pair later, after the captured key and client ID match.
     */
    if (!requestHooked) {
        throw new Error('Failed to attach PrepareKeyRequest in ' + name + '.');
    }

    if (successfulHookCount === 0) {
        throw new Error('No hooks attached for ' + name + ' after inspecting ' + entries.length + ' exports.');
    }

    const summary = 'Successfully hooked ' + successfulHookCount + ' function(s) from ' + entries.length + ' exports in ' + name;
    send('message_info', new TextEncoder().encode(summary));

    return successfulHookCount;
}

/* --------------------------------------------------------------------------
 * LIBRARY LOOKUP - used by Python while scanning attached processes.
 * Frida throws when the requested module is absent; Python handles that case.
 * -------------------------------------------------------------------------- */
function getModuleByName(lib) {
    return Process.getModuleByName(lib);
}

/* --------------------------------------------------------------------------
 * BINARY HELPERS - byte conversion and DER length parsing for private-key capture.
 * -------------------------------------------------------------------------- */
/* Preserve each byte as one character so getKeyLength can read it with charCodeAt. */
function a2bs(bytes) {
    let b = '';
    for (let i = 0; i < bytes.byteLength; i++)
        b += String.fromCharCode(bytes[i]);
    return b
}

/* Return the total DER object length, including its tag and length header.
 * The caller has already checked the 0x30, 0x82 prefix, so this helper expects
 * long-form length encoding. It is not a general ASN.1 parser or key validator.
 */
function getKeyLength(key) {
    let pos = 1 // Skip the tag
    let buf = key.charCodeAt(pos++);
    let len = buf & 0x7F; // Number of following length bytes

    buf = 0;
    for (let i = 0; i < len; ++i)
        buf = (buf * 256) + key.charCodeAt(pos++);
    return pos + Math.abs(buf);
}

/* --------------------------------------------------------------------------
 * PYTHON RPC ENTRY POINTS - names used by Helpers/Device.py.
 * getmodulebyname locates a module; hooklibfunctions installs its hooks.
 * Messages sent back to Python use private_key, device_info, and message_info.
 * -------------------------------------------------------------------------- */
rpc.exports.hooklibfunctions = hookLibFunctions;
rpc.exports.getmodulebyname = getModuleByName;
