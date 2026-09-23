# Implementation Agent Handoff

## Mission

Implement the controlled Olea-Dowsure Verifiable Data Oracle PoC described in this folder. The target is a narrow vertical slice for one or two approved Amazon SP-API endpoints, not unrestricted production hardening.

## Current Verified State (2026-09-24)

- Olea stack: `olea-oracle-preprod`, `UPDATE_COMPLETE`.
- Olea API: `https://c8tw99zmla.execute-api.ap-southeast-1.amazonaws.com/preprod`.
- Dowsure stack: `dowsure-oracle-preprod`, `UPDATE_COMPLETE`.
- Amazon mock: `amazon-sp-api-mock`, `CREATE_COMPLETE`.
- Nitro stack: `olea-dowsure-nitro-preprod`, `UPDATE_COMPLETE`.
- Nitro host: `i-0b2b6aa26fb920103`, private `c5.xlarge`, SSM Online, IMDSv2 required, no SSH ingress.
- Running enclave: `olea-orders-java`, CID `16`, `2` vCPUs, `2048 MiB`, phase4 EIF state `RUNNING`.
- Verified scope: one bounded `GET_ORDERS` flow.
- Local Phase 1 negative tests cover malformed CBOR, PCR mismatch, public-key mismatch, user-data mismatch, replay, expiry, envelope tampering, enclave-signature tampering, corrupted TLS proof, and TLS response-hash mismatch.
- The enclave runtime is now Java with Java AF_VSOCK; NSM access is isolated behind `AttestationProvider` and `JnaAttestationProvider`.
- The test harness is [poc-signed-evidence-test.js](scripts/poc-signed-evidence-test.js); the redacted evidence recorder is [phase1-evidence-report.js](scripts/phase1-evidence-report.js).
- Live non-debug evidence verification passed for request `293548c9-9975-4cc0-9039-b19a5ce6b421` and evidence `e826e531-cbc6-41ed-93d5-1da3ae68fe09`.
- Verification passed against the AWS Nitro Root-G1 certificate for COSE signature, certificate chain, PCR0/PCR1/PCR2, attested public key, and canonicalized `user_data` binding.
- The phase4 EIF SHA-256 `246e2143aeecb6c2e4f5e551536b2dfc75e8313fd521dd4da91da8f5d907da94` is registered `ACTIVE` in the preprod Olea release registry.

### Live Java EIF Measurements

- EIF: `/opt/olea-nitro/olea-orders-java-phase4.eif`, `464095310` bytes.
- Docker image: `olea-nitro-orders:java-phase4`, ID `5c7f299e46ffe90d8e2fadb0bb0808a7a171512cc84b6f3eb0d0de2d91f88ab3`.
- PCR0: `5fba63399c819c8658452d9d48f35ecd491f9d65d5d842eb7ada4ae23a63cb666796a643102c9cc9e71c8a4bc60baba9`.
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`.
- PCR2: `6560ff543ea448942b3f50ebadf606223a7aed1120856b503468a127671b22de6cbf195e0beb423b255100349e22c68f`.

## Next Steps

1. Replace the transitional API Gateway parent fixture with the coordinator service on the acceptance path.
2. Integrate an approved TLSNotary prover/notary service and verify real signed proof bundles; current code enforces only the proof contract and response-hash binding.
3. Add the live end-to-end evidence package and execute replay, expiry, PCR, key, envelope, and TLS tamper scenarios.

Do not describe the PoC as fully accepted until the live NSM document, configured Nitro root, and end-to-end receipt are captured.

## Read First

1. `README.md`
2. `olea-dowsure-executive-proposal.md`
3. `olea-dowsure-technical-design.md`
4. `dowsure-implementation-handoff.md`

The two files under `archive/` are historical summaries and are not authoritative.

## Architecture Decision

- Dowsure is the operational custodian.
- Olea owns source policy, challenge issuance, PCR/EIF trust registration, verification, acceptance, and immutable retention.
- For the two-week PoC, use the Dowsure-hosted Nitro Enclave model unless Olea already has ready enclave infrastructure.
- Dowsure calls the Olea Challenge API with request context.
- Olea returns a scoped challenge containing request ID, single-use nonce, policy version, endpoint scope, disclosure fields, and expiry.
- Dowsure dispatches the challenge and ephemeral LWA token to the enclave over vsock.
- The parent proxy forwards encrypted traffic and does not terminate or rewrite source TLS.
- The enclave acquires, hashes, transforms, attests, signs, and encrypts evidence to Olea.
- Dowsure signs a canonical submission envelope and submits the opaque evidence bundle to Olea.
- Olea verifies and returns acceptance or rejection with a reason code.

## Required Implementation Slices

### 1. Dowsure coordinator

Implement:

- Challenge request to Olea.
- Challenge validation: request ID, endpoint, operation, nonce, expiry, policy scope.
- Ephemeral LWA token exchange and memory-only handling.
- vsock dispatch to the enclave.
- Canonical submission envelope creation.
- Dowsure submission signature.
- Evidence submission and reason-code handling.

The coordinator must never log or persist tokens, raw payloads, PII, private keys, or full presigned URLs.

### 2. Parent proxy

Implement:

- Encrypted forwarding to approved SP-API/KYC/S3/Olea destinations.
- No TLS MITM.
- Host and port allowlists.
- Explicit rejection and metrics for denied destinations.
- Correlation IDs without sensitive payload logging.

### 3. Nitro Enclave application

Implement:

- Approved endpoint and operation enforcement.
- Synchronous Orders/Finances path for bounded requests.
- Reports API path: create, poll, getReportDocument, presigned S3 download.
- In-memory GZIP decompression.
- Raw-source hash before transformation.
- Approved deterministic transformation.
- Transformed-output hash.
- Ephemeral P-256 key generation.
- Nitro attestation binding public key, request ID, nonce, and policy version.
- Enclave signature over canonical manifest.
- Encryption of evidence to Olea before returning it to the parent.
- Private-key and sensitive-buffer cleanup.

### 4. Source proof

Support the approved proof mechanism per endpoint:

- Provider-native proof where genuinely available.
- TLSNotary/MPC-TLS only after real endpoint compatibility testing.
- Metadata-only TLSNotary proof must not be represented as proof of large report bytes.
- Unsupported source-proof paths fail closed or require an explicit residual-risk exception.

### 5. Evidence contract

The evidence manifest must bind:

- Request/evidence ID.
- Source, endpoint, operation, parameters, account/marketplace context.
- Nonce, policy version, issue time, and expiry.
- Source-proof type, reference, and hash.
- Raw-source hash.
- Transformation version and manifest.
- Transformed-output hash.
- EIF release, PCRs, attestation document, and attested public key.
- Enclave signature.
- Submission envelope digest and Dowsure signature.

The Dowsure submission envelope must cover:

- Manifest digest.
- Encrypted-evidence digest.
- Request ID.
- Nonce.
- Policy version.
- Submission timestamp.

### 6. Scheduled transaction profile

If implementing the financial transaction flow:

- Capture request-level raw-response hash.
- Capture pagination and completeness metadata.
- Filter qualified transactions only after trusted raw capture.
- Calculate per-transaction `receipt_hash` from versioned canonical transaction JSON.
- Produce `integrity_metadata.json` alongside financing Excel.
- Keep `transactionId` and `postedDate` as reconciliation fields, not source proof.
- Preserve filter version, canonicalization version, source-proof reference, and included/excluded transaction metadata where policy permits.

## Explicit Interfaces to Define Before Coding

Do not invent or randomly call undefined services. Define schemas and implementations for:

- `OleaClient.requestChallenge(...)`
- `OleaClient.submitEvidence(...)`
- `EnclaveClient.acquire(...)`
- `SourceClient.fetchApproved(...)`
- `SourceProofProvider.proveResponse(...)`
- `SourceProofProvider.proveReportMetadata(...)`
- `TransformationEngine.apply(...)`
- `EvidenceEncryptor.encryptForOlea(...)`
- `SubmissionSigner.sign(...)`
- `Canonicalizer.canonicalize(...)`
- `Nonce/Challenge response reason codes`

Use Java for service examples and implementation where the target Dowsure service is Java. Keep cloud/vendor APIs behind typed adapters.

## EIF Governance

- Every EIF code change has a named owner and PR reviewer.
- CI runs tests, dependency scans, SBOM generation, reproducible build, EIF creation, and PCR measurement.
- Dowsure submits the signed release manifest and EIF digest to Olea.
- Dowsure deploys only after Olea registers the exact digest/PCR set as active.
- Revoked releases are terminal for new evidence.
- Emergency changes require rollback evidence and retrospective review.

## Acceptance Tests

The implementation is PoC-ready only when it demonstrates:

- Dowsure requests an Olea challenge for every policy-covered request.
- Missing, expired, mismatched, or out-of-scope challenges fail closed.
- The selected endpoints work through the approved path.
- No source side path bypasses the enclave.
- Tokens and sensitive payloads are absent from logs, disk, and EIF.
- Reports API and presigned S3 processing work inside enclave memory.
- Raw and transformed hashes reproduce independently.
- Source proof binds to the raw-source hash.
- Nitro attestation and PCRs match Olea’s registered release.
- Submission-envelope signatures validate.
- Invalid, stale, replayed, tampered, and revoked-release evidence is rejected.
- Monitoring, rollback, and support ownership are demonstrated.

## Out of Scope for This Agent

- Full production multi-region hardening.
- Broad endpoint/provider expansion.
- Funder CLI productization.
- Business-policy decisions owned by Olea Risk, Legal, or leadership.
- Changing the architecture without an explicit decision record.

## Final Deliverable

Return:

- Implemented code and tests.
- API/schema definitions.
- EIF build and PCR evidence.
- Local/PoC deployment instructions.
- Negative-test results.
- Open risks and blockers.
- A short implementation report mapped to the acceptance criteria above.
