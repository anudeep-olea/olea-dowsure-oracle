# Nitro Enclave PoC

This folder contains the Java enclave runtime used to prove the Nitro attestation path.

## What it does

- runs a Java service inside a real Nitro enclave,
- accepts a bounded mock request over AF_VSOCK,
- calculates raw and transformed hashes,
- binds request metadata to the attestation user_data payload,
- generates an ephemeral keypair,
- requests a real Nitro attestation document,
- returns an evidence package that can be verified by Olea.

## Why it matters

This is the part that proves the trusted execution environment is real. The enclave is not just a simulator; it is a real AWS Nitro-attested runtime that can produce a signed attestation document and measured PCR values.

## Current status

The enclave is already running successfully in non-debug mode and passed live verification:

- real AWS Root-G1 validation passed,
- COSE signature checks passed,
- certificate chain checks passed,
- PCR values matched,
- public key binding matched,
- user_data binding matched,
- the exact EIF release was registered as active.

## Important limitation

The enclave is real and working, but the upstream source proof is not yet real. We still lack the approved TLSNotary/notary infrastructure needed to prove the exact upstream response over a real TLS session. That means the enclave path is proven, but the full source-proof chain is still gated by the external notary dependency.

## Native boundary

The Java code talks to the AWS Nitro NSM library through the pinned native boundary. This is the expected pattern for Nitro enclaves and is deliberately isolated from the general application logic.

## In plain English

This part proves “the code ran inside a real Nitro enclave with a trusted measurement.” It does not yet prove “the remote source response is authentic by TLSNotary” because that external proof layer is still missing.
