# Project status matrix

This matrix explains the current state of the Olea-Dowsure verifiable data oracle PoC.

| Area | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Nitro host / EC2 environment | Verified | Real Nitro-capable EC2 host is running | Host is live and SSM-managed |
| Java enclave runtime | Verified | Enclave is running in non-debug mode | `olea-orders-java` is active |
| EIF generation | Verified | EIF exists and was measured | Real EIF created and registered |
| AWS Nitro attestation | Verified | Attestation document is produced by NSM | Verified against AWS Root-G1 |
| COSE signature validation | Verified | Certificate and signature chain validated | Passes live verification |
| PCR / measurement validation | Verified | PCR0, PCR1, PCR2 match approved baseline | Enforce fail-closed validation |
| public key binding | Verified | Attested public key matches expected binding | Included in user_data checks |
| `user_data` canonicalization | Verified | Canonicalized binding accepted | JSON canonicalization and hash binding passed |
| EIF release registration | Verified | Exact EIF SHA-256 is registered active | Release registry is populated |
| vsock communication | Verified | Java AF_VSOCK path is live | Port `5005` is active |
| mock upstream source flow | Verified | Controlled mock source request path works | A bounded `GET_ORDERS` path is in place |
| TLSNotary proof integration | Blocked | No approved notary/prover infrastructure available | This is the critical open gate |
| real upstream source proof | Blocked | Not yet approved or connected | No Amazon proof path is claimed |
| full Olea acceptance receipt | Blocked | Acceptance flow is not complete | Evidence package is not yet accepted end-to-end |
| coordinator integration | Open | Transitional path remains in place | Final coordinator path still needs to replace the fixture |
| production Amazon onboarding | Out of scope | Explicitly deferred | Phase 2 work only |

## Plain-English summary

The project is successfully proving the trusted-execution and attestation architecture. It is not yet proving a real upstream source-authenticity layer because the external TLSNotary infrastructure and approved proof material are not available.

## Decision statement

The current honest position is:

- the enclave and attestation path is real and validated,
- the trust model is working for the controlled PoC,
- the upstream TLSNotary proof layer remains blocked by missing external dependencies.

This project should be described as a real attestation PoC with a blocked source-proof gate, not as a completed Amazon-origin verification deployment.
