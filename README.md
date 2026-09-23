# Olea-Dowsure Verifiable Data Oracle

This repository is the working PoC for a verifiable data ingestion flow that uses:

- a real AWS Nitro Enclave,
- attestation verification against AWS Nitro root material,
- PCR and enclave-key validation,
- a bounded mock source flow,
- and a Dowsure/Olea evidence verification handshake.

This is not a production Amazon-side integration yet. It is a controlled trust-validation prototype designed to prove the architecture works before onboarding real upstream data sources.

## What is done

The PoC already proves the following end-to-end trust path:

- a Java enclave is running in a real Nitro-capable EC2 environment,
- the enclave is launched from an EIF and runs without debug mode,
- attestation is produced from Nitro NSM instead of a synthetic mock,
- the attestation document is validated with the AWS Nitro root certificate,
- PCR0, PCR1, and PCR2 are checked,
- the attested public key and canonicalized user_data bindings are verified,
- the enclave response is hashed and transformed deterministically,
- the hash chain is accepted by the verifier in the live non-debug case,
- the EIF digest was registered in the preprod release registry as active.

### Verified live status

The current evidence indicates:

- enclave is running as `olea-orders-java`,
- Java AF_VSOCK path is active on port `5005`,
- live attestation passed AWS Root-G1 validation,
- COSE and certificate chain checks passed,
- PCR and public-key verification passed,
- `user_data` binding passed,
- exact EIF SHA-256 was registered as active.

## What is not complete

This is the important part:

- the project does not yet have a real TLSNotary prover/notary integration,
- the proof system in the code is a contract check, not a real TLSNotary proof validation,
- the current source flow is still a controlled mock endpoint,
- the full Olea acceptance receipt and real upstream source-proof flow remain open work.

This project is therefore best described as a real attestation-and-verification PoC with a blocked TLSNotary gate.

## Why TLSNotary is blocked here

We cannot simply “do TLS” in the normal sense for this use case because the requirement is not just HTTPS. The requirement is source proof that the exact upstream response was seen over a TLS connection and that the proof is accepted by a trusted notary.

That requires all of the following to exist and to be compatible with the actual endpoint:

- a TLSNotary-compatible upstream endpoint,
- a prover/client that can participate in the handshake,
- a notary service that signs the proof,
- an approved notary public key that Olea trusts,
- a forwarding/proxy path acceptable to the endpoint,
- a verifier that checks the full proof bundle,
- a request/response binding that matches the specific fetch and the hash we are validating.

For this project, the blocker is not the enclave. The blocker is that the external notary/prover infrastructure and approved proof material are not available here. Without those, the code can only validate a hash-contract placeholder, not a real TLSNotary proof. That is why the implementation is deliberately fail-closed and flagged as incomplete.

## Repository layout

- [sam](sam/README.md): SAM-based PoC deployment, verification function, and mock source setup.
- [nitro-enclave](nitro-enclave/README.md): Java Nitro enclave implementation and EIF/runtime notes.
- [coordinator](coordinator): coordinator and vsock flow logic.
- [infra](infra): infrastructure-related materials.
- [scripts](scripts): evidence and validation helpers.
- [tests](tests): test harnesses and validation scripts.
- [archive](archive): historical documents kept for traceability only.

## Important documents

- [olea-dowsure-executive-proposal.md](olea-dowsure-executive-proposal.md)
- [olea-dowsure-technical-design.md](olea-dowsure-technical-design.md)
- [dowsure-implementation-handoff.md](dowsure-implementation-handoff.md)
- [IMPLEMENTATION_AGENT_HANDOFF.md](IMPLEMENTATION_AGENT_HANDOFF.md)
- [sam/docs/ARCHITECTURE_SUMMARY.md](sam/docs/ARCHITECTURE_SUMMARY.md)
- [sam/docs/POC_LIMITATIONS.md](sam/docs/POC_LIMITATIONS.md)

## Plain-English summary

If you only want the short version:

- the enclave and attestation path are real,
- the trust chain is verified,
- the measurement was registered,
- the current proof path is still incomplete because the real notary-backed TLS proof is missing,
- we are not claiming Amazon-origin verification yet,
- the project is a valid architecture and trust proof, but not a completed production source-integrity deployment.

## Recommended next step

The next hard gate is to obtain:

1. an approved TLSNotary prover,
2. a compatible upstream endpoint,
3. the approved notary public key,
4. a real signed proof bundle,
5. a verifier that enforces the real proof and request/response binding.

Once those are provided, the code can be upgraded from “proof contract validation” to “real TLSNotary verification” and the acceptance flow can be closed.
