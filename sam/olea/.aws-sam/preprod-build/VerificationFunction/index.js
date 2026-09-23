'use strict';

const crypto = require('node:crypto');
const {DynamoDBClient} = require('@aws-sdk/client-dynamodb');
const {DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand} = require('@aws-sdk/lib-dynamodb');
const {KMSClient, SignCommand} = require('@aws-sdk/client-kms');
const {PutObjectCommand, S3Client} = require('@aws-sdk/client-s3');

const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const kms = new KMSClient({});
const s3 = new S3Client({});
const APPROVED_ENDPOINTS = new Set(['GET_ORDERS', 'GET_FINANCIAL_EVENTS', 'CREATE_REPORT', 'GET_REPORT', 'GET_REPORT_DOCUMENT']);

function response(statusCode, body) {
  return {statusCode, headers: {'content-type': 'application/json', 'cache-control': 'no-store'}, body: JSON.stringify(body)};
}

function parseBody(event) {
  try { return JSON.parse(event.body || '{}'); } catch { return null; }
}

async function get(tableName, key) {
  return (await dynamo.send(new GetCommand({TableName: tableName, Key: key, ConsistentRead: true}))).Item;
}

function canonicalize(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('NON_CANONICAL_NUMBER');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  throw new Error('NON_CANONICAL_VALUE');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function verifySignature(publicKeyPem, payload, signature) {
  return crypto.verify('sha256', Buffer.from(payload), publicKeyPem, Buffer.from(signature, 'base64'));
}

function decodePocAttestation(encoded) {
  const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
  const document = JSON.parse(decoded);
  if (document.format !== 'olea-poc-attestation-v1') throw new Error('ATTESTATION_FORMAT_INVALID');
  return document;
}

function verifyPocAttestation(document, release, binding) {
  const unsigned = {...document};
  delete unsigned.signature;
  if (!release.attestationPublicKeyPem || !document.signature) throw new Error('ATTESTATION_KEY_MISSING');
  if (!verifySignature(release.attestationPublicKeyPem, canonicalize(unsigned), document.signature)) throw new Error('ATTESTATION_SIGNATURE_INVALID');
  if (document.pcr0 !== release.pcr0 || document.pcr1 !== release.pcr1 || document.pcr2 !== release.pcr2) throw new Error('PCR_MISMATCH');
  if (document.publicKeyPem !== release.attestedPublicKeyPem) throw new Error('ATTESTED_KEY_MISMATCH');
  if (document.userData !== sha256(canonicalize(binding))) throw new Error('ATTESTATION_BINDING_INVALID');
}

async function issueChallenge(body) {
  const required = ['requestId', 'source', 'endpoint', 'operation', 'marketplaceId', 'accountId'];
  if (!body || required.some((field) => !body[field])) return response(400, {status: 'REJECTED', reasonCode: 'INVALID_REQUEST'});
  if (body.source !== 'AMAZON_SP_API' || !APPROVED_ENDPOINTS.has(body.endpoint)) {
    return response(403, {status: 'REJECTED', reasonCode: 'CHALLENGE_ENDPOINT_MISMATCH'});
  }

  const policy = await get(process.env.POLICY_TABLE, {policyVersion: body.policyVersion || 'v1.0'});
  if (!policy || policy.status !== 'ACTIVE' || !policy.endpointScope.includes(body.endpoint)) {
    return response(403, {status: 'REJECTED', reasonCode: 'POLICY_VERSION_REVOKED'});
  }

  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + Number(process.env.CHALLENGE_TTL_SECONDS) * 1000);
  const challenge = {
    requestId: body.requestId,
    nonce: crypto.randomBytes(32).toString('base64url'),
    policyVersion: policy.policyVersion,
    endpointScope: [body.endpoint],
    transformationVersion: policy.transformationVersion,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    used: false,
    ttl: Math.floor(expiresAt.getTime() / 1000)
  };
  const digest = crypto.createHash('sha256').update(JSON.stringify(challenge)).digest();
  const signed = await kms.send(new SignCommand({KeyId: process.env.OLEA_SIGNING_KEY_ID, Message: digest, MessageType: 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256'}));
  challenge.challengeSignature = Buffer.from(signed.Signature).toString('base64');
  await dynamo.send(new PutCommand({TableName: process.env.CHALLENGE_TABLE, Item: challenge, ConditionExpression: 'attribute_not_exists(requestId)'}));
  delete challenge.used;
  delete challenge.ttl;
  return response(201, challenge);
}

async function submitEvidence(body) {
  const required = ['requestId', 'evidenceId', 'nonce', 'policyVersion', 'endpoint', 'encryptedEvidenceReference', 'manifestDigest', 'submissionEnvelope', 'submissionSignature', 'rawPayload', 'rawPayloadDigest', 'transformedPayload', 'transformedPayloadDigest', 'canonicalizationVersion', 'attestationDocument', 'eifDigest', 'pcr0', 'pcr1', 'pcr2'];
  if (!body || required.some((field) => !body[field])) return response(400, {status: 'REJECTED', reasonCode: 'PAYLOAD_CORRUPTED'});

  const challenge = await get(process.env.CHALLENGE_TABLE, {requestId: body.requestId});
  if (!challenge) return response(404, {status: 'REJECTED', reasonCode: 'CHALLENGE_NOT_FOUND'});
  if (challenge.used) return response(409, {status: 'REJECTED', reasonCode: 'CHALLENGE_REPLAY'});
  if (Date.parse(challenge.expiresAt) <= Date.now()) return response(410, {status: 'REJECTED', reasonCode: 'CHALLENGE_EXPIRED'});
  if (body.nonce !== challenge.nonce) return response(422, {status: 'REJECTED', reasonCode: 'NONCE_MISMATCH'});
  if (body.policyVersion !== challenge.policyVersion) return response(422, {status: 'REJECTED', reasonCode: 'POLICY_VERSION_REVOKED'});
  if (!challenge.endpointScope.includes(body.endpoint)) return response(422, {status: 'REJECTED', reasonCode: 'CHALLENGE_SCOPE_MISMATCH'});
  const release = await get(process.env.RELEASE_TABLE, {eifDigest: body.eifDigest});
  if (!release) return response(422, {status: 'REJECTED', reasonCode: 'PCR_MISMATCH'});
  if (release.status === 'REVOKED') return response(422, {status: 'REJECTED', reasonCode: 'EIF_REVOKED'});
  if (['pcr0', 'pcr1', 'pcr2'].some((field) => body[field] !== release[field])) return response(422, {status: 'REJECTED', reasonCode: 'PCR_MISMATCH'});

  try {
    if (body.canonicalizationVersion !== 'RFC8785-PoC') throw new Error('CANONICALIZATION_VERSION_UNSUPPORTED');
    if (sha256(canonicalize(body.rawPayload)) !== body.rawPayloadDigest) throw new Error('RAW_PAYLOAD_HASH_MISMATCH');
    if (sha256(canonicalize(body.transformedPayload)) !== body.transformedPayloadDigest) throw new Error('TRANSFORMED_PAYLOAD_HASH_MISMATCH');
    const manifest = {requestId: body.requestId, evidenceId: body.evidenceId, rawPayloadDigest: body.rawPayloadDigest, transformedPayloadDigest: body.transformedPayloadDigest, canonicalizationVersion: body.canonicalizationVersion};
    const envelope = canonicalize(body.submissionEnvelope);
    if (sha256(canonicalize(manifest)) !== body.manifestDigest) throw new Error('MANIFEST_HASH_MISMATCH');
    const expectedEnvelope = {requestId: body.requestId, nonce: body.nonce, policyVersion: body.policyVersion, evidenceId: body.evidenceId, manifestDigest: body.manifestDigest, encryptedEvidenceReference: body.encryptedEvidenceReference, submittedAt: body.submissionEnvelope.submittedAt};
    if (canonicalize(body.submissionEnvelope) !== canonicalize(expectedEnvelope)) throw new Error('SUBMISSION_ENVELOPE_INVALID');
    if (!release.dowsurePublicKeyPem || !verifySignature(release.dowsurePublicKeyPem, envelope, body.submissionSignature)) throw new Error('DOWSURE_SIGNATURE_INVALID');
    const attestation = decodePocAttestation(body.attestationDocument);
    verifyPocAttestation(attestation, release, {requestId: body.requestId, nonce: body.nonce, policyVersion: body.policyVersion, manifestDigest: body.manifestDigest});
  } catch (error) {
    const reasonCode = error.message === 'DOWSURE_SIGNATURE_INVALID' ? error.message : error.message;
    return response(422, {status: 'REJECTED', reasonCode});
  }

  try {
    await dynamo.send(new UpdateCommand({TableName: process.env.CHALLENGE_TABLE, Key: {requestId: body.requestId}, UpdateExpression: 'SET used = :true', ConditionExpression: 'used = :false AND nonce = :nonce', ExpressionAttributeValues: {':true': true, ':false': false, ':nonce': body.nonce}}));
  } catch (error) {
    if (error.name === 'ConditionalCheckFailedException') return response(409, {status: 'REJECTED', reasonCode: 'SUBMISSION_REPLAY'});
    throw error;
  }

  const receipt = {evidenceId: body.evidenceId, requestId: body.requestId, status: 'ACCEPTED', reasonCode: 'SUCCESS', manifestDigest: body.manifestDigest, acceptedAt: new Date().toISOString()};
  await s3.send(new PutObjectCommand({Bucket: process.env.EVIDENCE_VAULT, Key: `evidence/${body.evidenceId}.json`, Body: JSON.stringify(body), ContentType: 'application/json', ServerSideEncryption: 'aws:kms'}));
  await dynamo.send(new PutCommand({TableName: process.env.RECEIPT_TABLE, Item: receipt}));
  return response(202, receipt);
}

async function handler(event) {
  const body = parseBody(event);
  if (body === null) return response(400, {status: 'REJECTED', reasonCode: 'PAYLOAD_CORRUPTED'});
  const path = event.resource;
  try {
    if (event.httpMethod === 'POST' && path === '/v1/challenges') return issueChallenge(body);
    if (event.httpMethod === 'POST' && path === '/v1/evidence') return submitEvidence(body);
    if (event.httpMethod === 'POST' && path === '/v1/policies') {
      if (!body.policyVersion || !Array.isArray(body.endpointScope) || !body.transformationVersion) return response(400, {status: 'REJECTED', reasonCode: 'INVALID_REQUEST'});
      await dynamo.send(new PutCommand({TableName: process.env.POLICY_TABLE, Item: {...body, status: body.status || 'ACTIVE'}}));
      return response(201, {status: 'REGISTERED', policyVersion: body.policyVersion});
    }
    if (event.httpMethod === 'GET' && path === '/v1/policies/{policyVersion}') {
      const item = await get(process.env.POLICY_TABLE, {policyVersion: event.pathParameters.policyVersion});
      return item ? response(200, item) : response(404, {status: 'REJECTED', reasonCode: 'POLICY_NOT_FOUND'});
    }
    if (event.httpMethod === 'POST' && path === '/v1/releases') {
      if (!body.eifDigest || !body.pcr0 || !body.pcr1 || !body.pcr2) return response(400, {status: 'REJECTED', reasonCode: 'INVALID_REQUEST'});
      await dynamo.send(new PutCommand({TableName: process.env.RELEASE_TABLE, Item: {...body, status: 'ACTIVE'}}));
      return response(201, {status: 'REGISTERED', eifDigest: body.eifDigest});
    }
    if (event.httpMethod === 'GET' && path === '/v1/releases/{eifDigest}') {
      const item = await get(process.env.RELEASE_TABLE, {eifDigest: event.pathParameters.eifDigest});
      return item ? response(200, item) : response(404, {status: 'REJECTED', reasonCode: 'EIF_NOT_FOUND'});
    }
    if (event.httpMethod === 'POST' && path === '/v1/releases/{eifDigest}/revoke') {
      await dynamo.send(new UpdateCommand({TableName: process.env.RELEASE_TABLE, Key: {eifDigest: event.pathParameters.eifDigest}, UpdateExpression: 'SET #status = :status', ExpressionAttributeNames: {'#status': 'status'}, ExpressionAttributeValues: {':status': 'REVOKED'}, ConditionExpression: 'attribute_exists(eifDigest)'}));
      return response(200, {status: 'REVOKED', eifDigest: event.pathParameters.eifDigest});
    }
    if (event.httpMethod === 'GET' && path === '/v1/receipts/{evidenceId}') {
      const item = await get(process.env.RECEIPT_TABLE, {evidenceId: event.pathParameters.evidenceId});
      return item ? response(200, item) : response(404, {status: 'REJECTED', reasonCode: 'RECEIPT_NOT_FOUND'});
    }
    return response(404, {status: 'REJECTED', reasonCode: 'NOT_FOUND'});
  } catch (error) {
    const reasonCode = error.name === 'ConditionalCheckFailedException' ? 'CONFLICT' : 'INTERNAL_ERROR';
    console.error(JSON.stringify({message: 'Olea request failed', requestId: body && body.requestId, error: error.name}));
    return response(reasonCode === 'CONFLICT' ? 409 : 500, {status: 'REJECTED', reasonCode});
  }
}

module.exports = {handler, issueChallenge, submitEvidence};
