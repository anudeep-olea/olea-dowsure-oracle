# Phase 1 Agent Mission: Olea Verifiable Data Oracle

Phase 1 validates the trust architecture, not Amazon onboarding. Use a controlled mock source API and deliver a PoC-ready end-to-end flow with real [[Olea]], a real [[AWS Nitro Enclave]], AWS Nitro attestation, PCR verification, vsock communication, and [[TLSNotary]].

**Amazon integration is explicitly removed from Phase 1.** Do not spend Phase 1 effort on Amazon SP-API, LWA OAuth, seller accounts, Reports API, financial reports, presigned S3 downloads, or Amazon source claims. Those are Phase 2 work.

## Success Criteria

The PoC must prove:

```text
Mock source response
  -> TLSNotary proof
  -> Nitro Enclave
  -> raw hash
  -> deterministic transformation
  -> transformed hash
  -> AWS Nitro attestation
  -> Dowsure envelope signature
  -> Olea verification
  -> immutable evidence retention
```

The acceptable claim is: “Source-proof validated data was processed inside an AWS Nitro Enclave running an approved EIF, attested using AWS Nitro Attestation, verified against registered PCR measurements, and accepted through Olea's challenge-based evidence verification process.”

Do not claim Amazon-origin verification. Use “source-proof verified using TLSNotary against the Olea-approved mock endpoint” until a real Amazon endpoint is separately tested and approved.

## Phase 1 Components

- **[[Olea Side]]**
  - Template: [../olea/template.yaml](../olea/template.yaml)
  - Code: [../olea/functions/verification/index.js](../olea/functions/verification/index.js)
  - Owns challenge issuance, single-use nonce state, source policy, transformation-version registry, EIF digest/PCR/revocation registry, evidence verification, receipts, and the KMS-encrypted S3 Object Lock evidence vault.
  - Replace the current PoC JSON attestation verifier with real Nitro CBOR/COSE verification.

- **[[Dowsure Side]]**
  - Template: [../dowsure/template.yaml](../dowsure/template.yaml)
  - Workflow: [../dowsure/statemachine/acquisition.asl.json](../dowsure/statemachine/acquisition.asl.json)
  - Implement the Java coordinator: request and validate the challenge, dispatch over vsock, receive encrypted evidence, create the canonical envelope, sign it, and submit it to Olea.
  - Keep only request/challenge metadata, job status, and opaque evidence references in workflow state.
  - Never log or store raw payloads, TLS proofs, tokens, decrypted evidence, private keys, presigned URLs, or task tokens.
  - Do not redesign Step Functions in Phase 1.

- **[[Mock Source API]]**
  - Provide `GET /orders` at an Olea-approved controlled HTTPS endpoint.
  - Return a non-PII fixture such as `{ "orderId": "123", "amount": "100" }`.
  - Generate a TLSNotary proof containing `proofType`, `proofHash`, and `responseHash`.
  - The proof must bind cryptographically to the exact response consumed by the enclave.

- **[[Nitro Enclave]]**
  - Implement the Java enclave service behind real vsock communication.
  - Receive `requestId`, `nonce`, and `policyVersion`.
  - Fetch the mock source, validate the TLSNotary proof, compare its response hash with `rawSourceHash`, transform deterministically, and calculate `transformedHash`.
  - Generate an ephemeral P-256 keypair, request a real AWS Nitro attestation document, and bind the request metadata, both hashes, and public key in `user_data`.
  - Sign the manifest with the attested key and encrypt the evidence bundle to Olea's public key.
  - Return the encrypted bundle only.

## Olea Attestation Verification

Implement `AttestationVerifier` with this fail-closed sequence:

```text
Decode CBOR
  -> decode COSE
  -> validate AWS root
  -> validate certificate chain
  -> validate attestation signature
  -> extract and match PCR0/PCR1/PCR2
  -> reject revoked releases
  -> extract public key and user_data
  -> validate nonce, requestId, policyVersion, rawHash, transformedHash, and publicKey bindings
```

## Evidence Manifest

The manifest must contain `requestId`, `evidenceId`, `source: "mock-api"`, `endpoint: "GET_ORDERS"`, `nonce`, `policyVersion`, `rawSourceHash`, `transformedHash`, `tlsProofType: "tlsnotary"`, `tlsProofHash`, `pcr0`, `pcr1`, `pcr2`, `attestationDocument`, `attestedPublicKey`, `enclaveSignature`, and `dowsureSignature`.

## Mandatory Negative Tests

Automated tests must fail closed for invalid COSE signatures, wrong AWS roots or certificate chains, wrong PCR0/PCR1/PCR2, revoked releases, wrong public keys, wrong `user_data`, wrong or expired nonces, replay attacks, tampered raw or transformed hashes, invalid TLS proofs, TLS proof hash mismatches, and invalid Dowsure signatures.

## Live Validation Status (2026-09-24)

- **[[Nitro Host]]** `i-0b2b6aa26fb920103` (`olea-dowsure-nitro-preprod`, private subnet, SSM-managed) produced a non-zero Java EIF from Docker image `olea-nitro-orders:java-phase4`.
- The phase4 EIF is `/opt/olea-nitro/olea-orders-java-phase4.eif`, `464095310` bytes. `describe-eif` confirms Java entrypoint `java -jar /app/enclave-service.jar`, image ID `5c7f299e46ffe90d8e2fadb0bb0808a7a171512cc84b6f3eb0d0de2d91f88ab3`, CRC enabled, and unsigned EIF status.
- Phase4 PCRs are PCR0 `5fba63399c819c8658452d9d48f35ecd491f9d65d5d842eb7ada4ae23a63cb666796a643102c9cc9e71c8a4bc60baba9`, PCR1 `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`, and PCR2 `6560ff543ea448942b3f50ebadf606223a7aed1120856b503468a127671b22de6cbf195e0beb423b255100349e22c68f`.
- The Java enclave is `RUNNING` as `olea-orders-java`, CID `16`, `2` vCPUs, `2048 MiB`, with Java AF_VSOCK port `5005`.
- The enclave was restarted without `--debug-mode` and is `RUNNING` with `Flags: NONE`; debug-mode attestation was correctly rejected because PCR0/PCR1/PCR2 are zero in that mode.
- Live non-debug evidence was verified against the AWS Nitro Root-G1 certificate: COSE signature, certificate chain, PCR0/PCR1/PCR2, attested public key, and canonicalized `user_data` binding all passed.
- Verified evidence IDs: request `293548c9-9975-4cc0-9039-b19a5ce6b421`, evidence `e826e531-cbc6-41ed-93d5-1da3ae68fe09`.
- The exact phase4 EIF SHA-256 `246e2143aeecb6c2e4f5e551536b2dfc75e8313fd521dd4da91da8f5d907da94` is registered `ACTIVE` in the preprod Olea release registry.
- **Remaining gates**: complete the live Olea acceptance receipt and replace the TLSNotary proof contract with an approved prover/notary service and real signed proof verification. Coordinator integration remains open engineering work.

## Definition of Done

- Real Nitro enclave, AWS attestation document, AWS-root validation, COSE validation, PCR validation, vsock, and challenge binding work end to end.
- TLSNotary validates and binds to the raw response hash.
- Manifest and Dowsure signatures validate.
- Olea accepts valid evidence, rejects every negative case, and retains accepted evidence in the immutable vault.
- Amazon SP-API, LWA, seller accounts, reports, financial reports, presigned downloads, multi-region, production HA, governance automation, SBOM automation, and production onboarding remain explicitly deferred to Phase 2.

