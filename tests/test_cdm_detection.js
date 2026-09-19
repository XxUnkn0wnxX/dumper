const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Observed in the working Android 13 x86-64 libwvaidl.so. Its signature has
// three input parameters, an additional map, then two output string pointers.
// The implicit `this` pointer makes the first output Frida args[5].
const CURRENT_SIGNATURE = '_ZN5wvcdm10CdmLicense17PrepareKeyRequestERKNS_18InitializationDataERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEENS_14CdmLicenseTypeERKNS4_3mapISA_SA_NS4_4lessISA_EENS8_INS4_4pairISB_SA_EEEEEEPSA_SN_';
const UNKNOWN_SIGNATURE = '_ZN5wvcdm10CdmLicense17PrepareKeyRequestEUnknown';
const source = fs.readFileSync(path.join(__dirname, '../Helpers/script.js'), 'utf8');
const sdkSignatures = JSON.parse(fs.readFileSync(
    path.join(__dirname, 'fixtures/cdm_signatures.json'), 'utf8'));

function requestExport(name = CURRENT_SIGNATURE, address = 'request') {
    return { type: 'function', name, address };
}

function loadScript(version = 'auto', entries = [requestExport()], failAddress = null, options = {}) {
    const attached = [];
    const messages = [];
    const libraryName = options.libraryName || 'libwvaidl.so';
    const context = vm.createContext({
        rpc: { exports: {} },
        Process: {
            pointerSize: options.pointerSize || 8,
            getModuleByName(name) {
                assert.equal(name, libraryName);
                return { enumerateExports: () => entries };
            }
        },
        ptr: address => address,
        Interceptor: {
            attach(address, callbacks) {
                if (address === failAddress) {
                    throw new Error('simulated attach failure');
                }
                attached.push({ address, callbacks });
            }
        },
        send(kind, data) {
            if (kind === 'message_info') {
                messages.push(Buffer.from(data).toString('utf8'));
            }
        },
        console: { log() {} }
    });
    vm.runInContext(source.replace('${CDM_VERSION}', version)
        .replace('${DYNAMIC_FUNCTION_NAME}', ''), context, { timeout: 1000 });
    return {
        attached,
        messages,
        hook: () => context.rpc.exports.hooklibfunctions({ name: libraryName, base: '0x1000' })
    };
}

let passed = 0;
function test(name, callback) {
    callback();
    passed += 1;
    console.log('ok - ' + name);
}

function assertArgumentIndex(run, index) {
    const hook = run.attached.find(entry => entry.address === 'request');
    assert.ok(hook, 'request interceptor must be installed');
    const args = Array.from({ length: 7 }, (_, n) => ({ argument: n }));
    const invocation = {};
    hook.callbacks.onEnter.call(invocation, args);
    assert.equal(invocation.ret, args[index]);
}

test('auto uses the verified signature and captures args[5]', () => {
    const run = loadScript();
    assert.equal(run.hook(), 1);
    assertArgumentIndex(run, 5);
    assert.ok(run.messages.some(message => message.includes('Auto-detected') &&
        message.includes('args[5]') && message.includes('16.1.0 / 17.0.0')));
});

for (const fixture of sdkSignatures) {
    test('auto selects args[' + fixture.argumentIndex + '] for ' + fixture.name, () => {
        const run = loadScript('auto', [requestExport(fixture.symbol)], null, fixture);
        assert.equal(run.hook(), 1);
        assertArgumentIndex(run, fixture.argumentIndex);
        assert.ok(run.messages.some(message => message.includes('Auto-detected') &&
            message.includes('args[' + fixture.argumentIndex + ']')));
    });
}

for (const symbol of new Set(sdkSignatures.map(fixture => fixture.symbol))) {
    test('rejects an extra parameter on a verified SDK signature', () => {
        const run = loadScript('auto', [requestExport(symbol + 'b')]);
        assert.throws(run.hook, /unrecognized signature/);
        assert.equal(run.attached.length, 0);
    });
}

test('different recognized request layouts in one library are ambiguous', () => {
    const oldLayout = sdkSignatures.find(fixture => fixture.argumentIndex === 4);
    assert.ok(oldLayout, 'fixtures must include a verified older layout');
    const run = loadScript('auto', [requestExport(), requestExport(oldLayout.symbol, 'old-request')]);
    assert.throws(run.hook, /Expected one exported PrepareKeyRequest.*found 2/);
    assert.equal(run.attached.length, 0);
});

for (const [version, index] of [
    ['14.0.0', 4], ['15.0.0', 4], ['16.0.0', 4], ['16.1.0', 5], ['17.0.0', 5]
]) {
    test('manual ' + version + ' works with an unrecognized signature', () => {
        const run = loadScript(version, [requestExport(UNKNOWN_SIGNATURE)]);
        assert.equal(run.hook(), 1);
        assertArgumentIndex(run, index);
        assert.ok(run.messages.some(message => message.includes('Using manual CDM setting ' + version)));
        assert.ok(!run.messages.some(message => message.includes('Auto-detected')));
    });
}

test('an explicit setting takes precedence over auto detection', () => {
    const run = loadScript('14.0.0');
    run.hook();
    assertArgumentIndex(run, 4);
});

test('unknown signature fails before any interceptor is installed', () => {
    const run = loadScript('auto', [
        { type: 'function', name: 'candidate', address: 'private-key' },
        requestExport(UNKNOWN_SIGNATURE)
    ]);
    assert.throws(run.hook, /Cannot auto-detect.*--cdm-version/);
    assert.equal(run.attached.length, 0);
});

test('a changed signature containing the known method and map is rejected', () => {
    const run = loadScript('auto', [requestExport(CURRENT_SIGNATURE + 'b')]);
    assert.throws(run.hook, /unrecognized signature/);
    assert.equal(run.attached.length, 0);
});

for (const version of ['auto', '17.0.0']) {
    test(version + ' rejects missing request function before other hooks', () => {
        const run = loadScript(version, [{ type: 'function', name: 'candidate', address: 'private-key' }]);
        assert.throws(run.hook, /Expected one exported PrepareKeyRequest.*found 0/);
        assert.equal(run.attached.length, 0);
    });

    test(version + ' rejects ambiguous request functions', () => {
        const run = loadScript(version, [requestExport(), requestExport(UNKNOWN_SIGNATURE, 'overload')]);
        assert.throws(run.hook, /Expected one exported PrepareKeyRequest.*found 2/);
        assert.equal(run.attached.length, 0);
    });
}

test('data exports cannot serve as request functions', () => {
    const run = loadScript('auto', [{ ...requestExport(), type: 'variable' }]);
    assert.throws(run.hook, /found 0/);
    assert.equal(run.attached.length, 0);
});

test('data exports are not passed to Interceptor.attach', () => {
    const run = loadScript('auto', [
        requestExport(),
        { type: 'function', name: 'candidate', address: 'private-key' },
        { type: 'variable', name: 'qjmdhruq', address: 'data' },
        { type: 'variable', name: UNKNOWN_SIGNATURE, address: 'request-data' }
    ]);
    assert.equal(run.hook(), 2);
    assert.deepEqual(run.attached.map(entry => entry.address), ['request', 'private-key']);
});

test('request attachment failure does not report successful initialization', () => {
    const run = loadScript('auto', [
        { type: 'function', name: 'candidate', address: 'private-key' },
        requestExport()
    ], 'request');
    assert.throws(run.hook, /Failed to attach PrepareKeyRequest/);
    assert.ok(!run.messages.some(message => message.startsWith('Successfully hooked')));
});

test('an invalid manual version never falls back to args[4]', () => {
    const run = loadScript('18.0.0');
    assert.throws(run.hook, /Unsupported --cdm-version/);
    assert.equal(run.attached.length, 0);
});

console.log(passed + ' CDM detection checks passed.');
