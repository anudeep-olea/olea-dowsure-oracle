'use strict';

const crypto = require('node:crypto');

class CborReader {
  constructor(buffer) {
    this.buffer = Buffer.from(buffer);
    this.offset = 0;
  }

  read() {
    const initial = this.byte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    const length = this.length(additional);
    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2) return this.bytes(length);
    if (major === 3) return this.bytes(length).toString('utf8');
    if (major === 4) {
      const items = [];
      for (let index = 0; index < length; index += 1) items.push(this.read());
      return items;
    }
    if (major === 5) {
      const map = new Map();
      for (let index = 0; index < length; index += 1) map.set(this.read(), this.read());
      return map;
    }
    if (major === 6) {
      this.read();
      return this.read();
    }
    if (major === 7 && additional === 20) return false;
    if (major === 7 && additional === 21) return true;
    if (major === 7 && additional === 22) return null;
    throw new Error('ATTESTATION_CBOR_UNSUPPORTED');
  }

  byte() {
    if (this.offset >= this.buffer.length) throw new Error('ATTESTATION_CBOR_TRUNCATED');
    return this.buffer[this.offset++];
  }

  length(additional) {
    if (additional < 24) return additional;
    if (additional === 24) return this.byte();
    if (additional === 25) return this.buffer.readUInt16BE(this.take(2));
    if (additional === 26) return this.buffer.readUInt32BE(this.take(4));
    if (additional === 27) {
      const value = this.buffer.readBigUInt64BE(this.take(8));
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('ATTESTATION_CBOR_LENGTH_TOO_LARGE');
      return Number(value);
    }
    throw new Error('ATTESTATION_CBOR_INDEFINITE_UNSUPPORTED');
  }

  bytes(length) {
    return this.buffer.subarray(this.offset, this.offset = this.offset + length);
  }

  take(length) {
    const start = this.offset;
    this.offset += length;
    if (this.offset > this.buffer.length) throw new Error('ATTESTATION_CBOR_TRUNCATED');
    return start;
  }
}

function decodeCbor(value) {
  const reader = new CborReader(value);
  const decoded = reader.read();
  if (reader.offset !== reader.buffer.length) throw new Error('ATTESTATION_CBOR_TRAILING_DATA');
  return decoded;
}

function mapValue(map, key) {
  if (!(map instanceof Map) || !map.has(key)) throw new Error(`ATTESTATION_FIELD_MISSING:${key}`);
  return map.get(key);
}

function asBuffer(value, field) {
  if (!Buffer.isBuffer(value)) throw new Error(`ATTESTATION_FIELD_INVALID:${field}`);
  return value;
}

function asPem(value) {
  if (typeof value !== 'string') throw new Error('NITRO_ROOT_UNCONFIGURED');
  return value.includes('BEGIN CERTIFICATE') ? value : Buffer.from(value, 'base64').toString('utf8');
}

function normalizePem(value) {
  return value.replace(/\r/g, '').trim();
}

function verifyCertificate(child, issuer) {
  if (!child.verify(issuer.publicKey)) throw new Error('ATTESTATION_CERTIFICATE_CHAIN_INVALID');
}

function signatureToDer(signature) {
  if (signature.length !== 64 && signature.length !== 96) throw new Error('ATTESTATION_COSE_SIGNATURE_INVALID');
  const componentLength = signature.length / 2;
  const integer = (value) => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    let result = value.subarray(start);
    if (result[0] & 0x80) result = Buffer.concat([Buffer.from([0]), result]);
    return Buffer.concat([Buffer.from([0x02, result.length]), result]);
  };
  const r = integer(signature.subarray(0, componentLength));
  const s = integer(signature.subarray(componentLength));
  const body = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function verifyCoseSign1(signatureValue, certificate) {
  const sign1 = Array.isArray(signatureValue) ? signatureValue : decodeCbor(signatureValue);
  if (!Array.isArray(sign1) || sign1.length !== 4) throw new Error('ATTESTATION_COSE_INVALID');
  const protectedHeaders = asBuffer(sign1[0], 'protected');
  const payload = asBuffer(sign1[2], 'payload');
  const signature = asBuffer(sign1[3], 'signature');
  const headers = decodeCbor(protectedHeaders);
  const algorithm = headers instanceof Map ? headers.get(1) : undefined;
  const algorithms = {
    '-7': {hash: 'sha256', ecdsa: true},
    '-35': {hash: 'sha384', ecdsa: true},
    '-37': {hash: 'sha256', pss: true},
    '-38': {hash: 'sha384', pss: true},
    '-39': {hash: 'sha512', pss: true},
    '-257': {hash: 'sha256'},
    '-258': {hash: 'sha384'},
    '-259': {hash: 'sha512'},
  };
  const algorithmSpec = algorithms[String(algorithm)];
  if (!algorithmSpec) throw new Error('ATTESTATION_COSE_ALGORITHM_UNSUPPORTED');
  const structure = encodeCbor(['Signature1', protectedHeaders, Buffer.alloc(0), payload]);
  const verifier = crypto.createVerify(algorithmSpec.hash);
  verifier.update(structure);
  verifier.end();
  const encodedSignature = algorithmSpec.ecdsa ? signatureToDer(signature) : signature;
  const verifyOptions = algorithmSpec.pss ? {key: certificate.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST} : certificate.publicKey;
  if (!verifier.verify(verifyOptions, encodedSignature)) throw new Error('ATTESTATION_COSE_SIGNATURE_INVALID');
  return decodeCbor(payload);
}

function encodeCbor(value) {
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([encodeLength(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([encodeLength(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([encodeLength(4, value.length), ...value.map(encodeCbor)]);
  if (value instanceof Map) {
    const entries = [...value.entries()];
    return Buffer.concat([encodeLength(5, entries.length), ...entries.flatMap(([key, item]) => [encodeCbor(key), encodeCbor(item)])]);
  }
  throw new Error('ATTESTATION_CBOR_ENCODING_UNSUPPORTED');
}

function encodeLength(major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  if (length < 65536) return Buffer.from([(major << 5) | 25, length >> 8, length & 0xff]);
  throw new Error('ATTESTATION_CBOR_ENCODING_TOO_LARGE');
}

function publicKeyMatches(documentKey, expectedKey) {
  if (!expectedKey) throw new Error('ATTESTED_KEY_EXPECTED_MISSING');
  const expected = Buffer.from(expectedKey, 'base64');
  if (!documentKey.equals(expected)) throw new Error('ATTESTED_KEY_MISMATCH');
}

function validatePcrs(pcrs, release) {
  for (const [key, field] of [[0, 'pcr0'], [1, 'pcr1'], [2, 'pcr2']]) {
    const actual = asBuffer(pcrs instanceof Map ? pcrs.get(key) : undefined, `pcr${key}`).toString('hex');
    if (actual !== String(release[field]).toLowerCase()) throw new Error('PCR_MISMATCH');
  }
}

function validateUserData(value, binding) {
  if (value.toString('utf8') !== JSON.stringify(binding)) throw new Error('ATTESTATION_BINDING_INVALID');
}

function verifyNitroAttestation(encoded, release, binding) {
  const document = decodeCbor(Buffer.from(encoded, 'base64url'));
  const certificate = new crypto.X509Certificate(asBuffer(mapValue(document, 'certificate'), 'certificate'));
  const cabundle = mapValue(document, 'cabundle');
  if (!Array.isArray(cabundle) || cabundle.length === 0) throw new Error('ATTESTATION_CERTIFICATE_CHAIN_MISSING');
  const chain = cabundle.map((item) => new crypto.X509Certificate(asBuffer(item, 'cabundle')));
  verifyCertificate(certificate, chain[0]);
  for (let index = 0; index < chain.length - 1; index += 1) verifyCertificate(chain[index], chain[index + 1]);
  const root = new crypto.X509Certificate(asPem(process.env.NITRO_ROOT_CERT_PEM));
  if (normalizePem(chain[chain.length - 1].toLegacyObject().subject) === '') throw new Error('ATTESTATION_ROOT_INVALID');
  verifyCertificate(chain[chain.length - 1], root);

  const signedPayload = verifyCoseSign1(mapValue(document, 'signature'), certificate);
  const pcrs = mapValue(signedPayload, 'pcrs');
  validatePcrs(pcrs, release);
  const documentKey = asBuffer(mapValue(signedPayload, 'public_key'), 'public_key');
  publicKeyMatches(documentKey, release.attestedPublicKeyBase64);
  validateUserData(asBuffer(mapValue(signedPayload, 'user_data'), 'user_data'), binding);
  return {pcr0: String(release.pcr0).toLowerCase(), pcr1: String(release.pcr1).toLowerCase(), pcr2: String(release.pcr2).toLowerCase()};
}

module.exports = {decodeCbor, validatePcrs, validateUserData, publicKeyMatches, verifyNitroAttestation};
