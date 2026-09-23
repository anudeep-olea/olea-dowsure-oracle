# Quick start

## What this repo is

This repository is a PoC for a verifiable data oracle design using Nitro attestation and a Dowsure/Olea trust flow. It is designed to prove the architecture, not to claim production-grade upstream authenticity yet.

## The honest current status

This project is ready to show:

- a real Nitro enclave runtime,
- real attestation generation,
- real attestation verification,
- PCR checks,
- key and `user_data` binding,
- EIF measurement registration.

This project is not ready to claim:

- a real TLSNotary proof from a live approved notary,
- Amazon-origin verified data,
- full end-to-end production acceptance.

## How to read this project

Start here:

1. [README.md](../README.md)
2. [docs/PROJECT_STATUS_MATRIX.md](PROJECT_STATUS_MATRIX.md)
3. [docs/ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md)
4. [IMPLEMENTATION_AGENT_HANDOFF.md](../IMPLEMENTATION_AGENT_HANDOFF.md)
5. [sam/docs/POC_LIMITATIONS.md](../sam/docs/POC_LIMITATIONS.md)

## Main folders

- [sam](../sam)
  - SAM templates and the verification function
- [nitro-enclave](../nitro-enclave)
  - Java enclave runtime and attestation implementation
- [coordinator](../coordinator)
  - coordinator flow and vsock handoff logic
- [scripts](../scripts)
  - evidence and proof helper scripts
- [archive](../archive)
  - historical design notes only

## Recommended next milestone

The next hard gate is external to this repo:

- obtain approved TLSNotary prover infrastructure,
- get an approved notary public key,
- validate proof compatibility with the real upstream endpoint,
- verify real signed proofs before calling the source flow complete.

## Short version to share externally

This is a real Nitro attestation proof-of-concept with a blocked source-proof gate. The enclave and trust chain work. The notary-backed upstream proof is the remaining missing dependency.
