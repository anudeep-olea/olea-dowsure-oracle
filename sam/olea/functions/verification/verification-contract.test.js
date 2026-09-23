'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const {
  buildManifest,
  canonicalize,
  sha256,
  validateChallengeState,
  validateEnvelope,
  validateTlsProof,
  verifyEnclaveSignature,
} = require('./verification-contract');

const pair = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
const publicKey = pair.publicKey.export({type: 'spki', format: 'der'}).toString('base64');
const body = {
  requestId: 'request-1',
  evidenceId: 'evidence-1',
  source: 'mock-api',
  endpoint: 'GET_ORDERS',
  nonce: 'nonce-1',
  policyVersion: 'v1.0',
  rawPayloadDigest: 'a'.repeat(64),
  transformedPayloadDigest: 'b'.repeat(64),
  tlsProofType: 'tlsnotary',
  tlsProofHash: 'c'.repeat(64),
  canonicalizationVersion: 'RFC8785-PoC',
  attestedPublicKeyBase64: publicKey,
  encryptedEvidenceReference: 'vsock://opaque/evidence-1',
  manifestDigest: '',
  submissionEnvelope: {},
};
body.manifestDigest = sha256(canonicalize(buildManifest(body)));
body.submissionEnvelope = {
  requestId: body.requestId,
  nonce: body.nonce,
  policyVersion: body.policyVersion,
  evidenceId: body.evidenceId,
  manifestDigest: body.manifestDigest,
  encryptedEvidenceReference: body.encryptedEvidenceReference,
  submittedAt: '2026-09-23T00:00:00.000Z',
};

function proof(responseHash = body.rawPayloadDigest) {
  const value = {proofType: 'tlsnotary', responseHash, transcript: 'controlled-fixture'};
  return {...value, proofHash: sha256(canonicalize(value))};
}

test('rejects replayed challenge', () => {
  assert.throws(() => validateChallengeState({used: true, expiresAt: '2999-01-01T00:00:00.000Z', nonce: 'nonce-1', policyVersion: 'v1.0', endpointScope: ['GET_ORDERS']}, body), /CHALLENGE_REPLAY/);
});

test('rejects expired challenge', () => {
  assert.throws(() => validateChallengeState({used: false, expiresAt: '2020-01-01T00:00:00.000Z', nonce: 'nonce-1', policyVersion: 'v1.0', endpointScope: ['GET_ORDERS']}, body), /CHALLENGE_EXPIRED/);
});

test('rejects tampered envelope', () => {
  assert.throws(() => validateEnvelope({...body, submissionEnvelope: {...body.submissionEnvelope, nonce: 'tampered'}}), /SUBMISSION_ENVELOPE_INVALID/);
});

test('rejects tampered enclave manifest signature', () => {
  const manifest = buildManifest(body);
  const signature = crypto.sign('sha256', Buffer.from(canonicalize(manifest)), pair.privateKey).toString('base64');
  assert.throws(() => verifyEnclaveSignature({...body, enclaveSignature: signature.slice(0, -4) + 'AAAA'}, manifest), /ENCLAVE_SIGNATURE_INVALID/);
});

test('rejects corrupted TLS proof', () => {
  assert.throws(() => validateTlsProof({...proof(), proofHash: 'd'.repeat(64)}, body.rawPayloadDigest), /TLS_PROOF_INVALID/);
});

test('rejects TLS response hash mismatch', () => {
  assert.throws(() => validateTlsProof(proof('f'.repeat(64)), body.rawPayloadDigest), /TLS_PROOF_HASH_MISMATCH/);
});
