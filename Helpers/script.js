const DYNAMIC_FUNCTION_NAME = '${DYNAMIC_FUNCTION_NAME}';
const CDM_VERSION = '${CDM_VERSION}';

// These strings are function names that have been succesfully dumped.
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

// The TextEncoder/Decoder API isn't supported so it has to be polyfilled.
// Taken from https://gist.github.com/Yaffle/5458286#file-textencodertextdecoder-js
function TextEncoder() {
}

TextEncoder.prototype.encode = function (string) {
    var octets = [];
    var length = string.length;
    var i = 0;
    while (i < length) {
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
        octets.push(bits | (codePoint >> c));
        c -= 6;
        while (c >= 0) {
            octets.push(0x80 | ((codePoint >> c) & 0x3F));
            c -= 6;
        }
        i += codePoint >= 0x10000 ? 2 : 1;
    }
    return octets;
}

function getPrivateKey(address) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            if (!args[6].isNull()) {
                const size = args[6].toInt32();
                if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                    const buf = args[5].readByteArray(size);
                    const bytes = new Uint8Array(buf);
                    // The first two bytes of the DER encoding are 0x30 and 0x82 (MII).
                    if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                        try {
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

// nop privacy mode.
// PrivacyMode encrypts the payload with the public key returned by the license server which we don't want.
function disablePrivacyMode(address) {
    Interceptor.attach(address, {
        onLeave: function (retval) {
            retval.replace(ptr(0));
        }
    });
}

// Match complete observed signatures: a name fragment or Android version does
// not identify the ABI. These labels describe the existing argument layouts,
// not the exact plugin version installed on the device.
const PREPARE_KEY_REQUEST_LAYOUTS = {
    '_ZN5wvcdm10CdmLicense17PrepareKeyRequestERKNS_18InitializationDataERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEENS_14CdmLicenseTypeERKNS4_3mapISA_SA_NS4_4lessISA_EENS8_INS4_4pairISB_SA_EEEEEEPSA_SN_': {
        argumentIndex: 5,
        versions: '16.1.0 / 17.0.0'
    }
};

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
        layout = PREPARE_KEY_REQUEST_LAYOUTS[entry.name];
        send('message_info', new TextEncoder().encode(
            'Auto-detected PrepareKeyRequest layout in ' + libraryName + ': args[' +
            layout.argumentIndex + '] (CDM settings ' + layout.versions + ').'));
    } else {
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

function prepareKeyRequest(address, argumentIndex) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.ret = args[argumentIndex];
        },
        onLeave: function () {
            if (this.ret) {
                const size = ptr(this.ret).add(Process.pointerSize).readU32();
                const arr = this.ret.add(Process.pointerSize * 2).readPointer().readByteArray(size);
                send('device_info', arr);
            }
        }
    });
}

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

            if (hookedModule) {
                successfulHookCount += 1;
                const message = 'Hooked ' + hookedModule + ' at ' + module.address;
                send('message_info', new TextEncoder().encode(message));
            }
        } catch (e) {
            console.log("Error: " + e + " at F: " + module.name);
        }
    });

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

function getModuleByName(lib) {
    return Process.getModuleByName(lib);
}

function a2bs(bytes) {
    let b = '';
    for (let i = 0; i < bytes.byteLength; i++)
        b += String.fromCharCode(bytes[i]);
    return b
}

function getKeyLength(key) {
    let pos = 1 // Skip the tag
    let buf = key.charCodeAt(pos++);
    let len = buf & 0x7F; // Short tag length

    buf = 0;
    for (let i = 0; i < len; ++i)
        buf = (buf * 256) + key.charCodeAt(pos++);
    return pos + Math.abs(buf);
}

rpc.exports.hooklibfunctions = hookLibFunctions;
rpc.exports.getmodulebyname = getModuleByName;
