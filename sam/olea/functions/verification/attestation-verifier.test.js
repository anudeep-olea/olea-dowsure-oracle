'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {decodeCbor, publicKeyMatches, validatePcrs, validateUserData} = require('./attestation-verifier');

const release = {
  pcr0: '00'.repeat(48),
  pcr1: '11'.repeat(48),
  pcr2: '22'.repeat(48),
};

test('rejects truncated CBOR', () => {
  assert.throws(() => decodeCbor(Buffer.from([0x18])), /ATTESTATION_CBOR_TRUNCATED/);
});

test('decodes indefinite-length maps and arrays', () => {
  const decoded = decodeCbor(Buffer.from([0xbf, 0x01, 0x9f, 0x02, 0x03, 0xff, 0xff]));
  assert.deepEqual(decoded, new Map([[1, [2, 3]]]));
});

test('rejects wrong PCR measurements', () => {
  const pcrs = new Map([[0, Buffer.alloc(48)], [1, Buffer.alloc(48, 0x11)], [2, Buffer.alloc(48, 0x22)]]);
  pcrs.set(0, Buffer.alloc(48, 0xff));
  assert.throws(() => validatePcrs(pcrs, release), /PCR_MISMATCH/);
});

test('rejects wrong attested public key', () => {
  assert.throws(() => publicKeyMatches(Buffer.from('wrong'), Buffer.from('expected').toString('base64')), /ATTESTED_KEY_MISMATCH/);
});

test('rejects wrong user data binding', () => {
  assert.throws(() => validateUserData(Buffer.from('{"nonce":"wrong"}'), {nonce: 'expected'}), /ATTESTATION_BINDING_INVALID/);
});

test('accepts equivalent user data with different key order', () => {
  assert.doesNotThrow(() => validateUserData(Buffer.from('{"nonce":"expected","requestId":"r1"}'), {requestId: 'r1', nonce: 'expected'}));
});