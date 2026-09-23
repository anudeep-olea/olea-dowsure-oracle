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