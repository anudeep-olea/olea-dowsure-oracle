'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');

function usage() {
  console.error('Usage: node phase1-evidence-report.js --input coordinator-result.json --output phase1-evidence-summary.json');
  process.exit(2);
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const inputPath = argument('--input');
const outputPath = argument('--output');
if (!inputPath || !outputPath) usage();

const result = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
const evidence = result.evidence || result;
const attestation = evidence.attestationDocument;
if (!evidence.requestId || !evidence.evidenceId || !evidence.manifestDigest || !attestation) {
  throw new Error('PHASE1_EVIDENCE_FIELDS_MISSING');
}

const summary = {
  capturedAt: new Date().toISOString(),
  requestId: evidence.requestId || result.requestId,
  evidenceId: evidence.evidenceId || result.evidenceId,
  receiptId: evidence.receiptId || result.receiptId || null,
  status: evidence.status || result.status || 'SUBMITTED',
  reasonCode: evidence.reasonCode || result.reasonCode || null,
  pcr0: evidence.pcr0 || null,
  pcr1: evidence.pcr1 || null,
  pcr2: evidence.pcr2 || null,
  manifestSha256: evidence.manifestDigest,
  tlsProofSha256: evidence.tlsProofHash || null,
  attestationSha256: crypto.createHash('sha256').update(Buffer.from(attestation, 'base64url')).digest('hex'),
  source: evidence.source || 'mock-api',
  endpoint: evidence.endpoint || 'GET_ORDERS',
};

fs.writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
console.log(JSON.stringify(summary, null, 2));
