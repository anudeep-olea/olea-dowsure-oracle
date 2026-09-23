# PoC Limitations

- **[[Olea]]**
  - The verifier now requires Nitro CBOR/COSE documents, certificate-chain validation, AWS Nitro root configuration, PCR matching, attested public-key matching, and exact `user_data` binding.
  - The Java `JnaAttestationProvider` is wired to the pinned AWS `libnsm.so` ABI; the phase4 Java EIF has been rebuilt, the approved AWS Nitro root has been used, and a non-debug document has passed live verification.
  - Authentication and authorization for administrative policy/release endpoints must be added before production.
  - Synthetic JSON attestation is no longer accepted by the source verifier or enclave runtime.

- **[[Dowsure]]**
  - A real Nitro-capable EC2 host and running EIF now exist in the preprod account; the deployed Step Functions parent API remains a static fixture.
  - The Phase 1 end-to-end slice covers one bounded `GET_ORDERS` request against the approved mock source API.
  - Phase 1 must prove TLSNotary source-proof binding, real vsock integration, and real Nitro attestation; it must not claim Amazon source authenticity.
  - The fixture immediately reports completion after one poll.
  - The EventBridge connection uses one PoC API-key credential for both endpoint families.
  - Production should use approved endpoint-specific authentication and private connectivity where required.
  - The coordinator now targets AF_VSOCK CID `16`, port `5005`; the API Gateway parent fixture remains only a transitional transport for the Step Functions integration.

- **[[Mock Source API]]**
  - Responses are controlled fixtures and are not Amazon source proof.
  - TLSNotary compatibility and proof-to-response hash binding remain mandatory Phase 1 implementation gates.

- **Assurance Boundary**
  - No mock output can be described as verified Amazon evidence.
  - The Nitro host and phase4 Java EIF are real and running; the phase4 EIF SHA-256 is registered `ACTIVE` in preprod. Remaining Phase 1 gaps are approved TLSNotary prover/notary integration, encrypted evidence transfer, and replacing the transitional Step Functions parent fixture with the coordinator service.
  - Amazon SP-API, LWA, seller accounts, reports, financial reports, presigned downloads, and Amazon endpoint compatibility are Phase 2 concerns.
  - Production acceptance requires real EIF measurements, Nitro attestation, signatures, deterministic canonicalization, and independently reproducible hashes.
