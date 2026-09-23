# Architecture diagram

```mermaid
flowchart LR
    A[Approved Source Endpoint] --> B[Source Request / Response]
    B --> C[TLSNotary Prover / Notary
    (required, but currently blocked)]
    C --> D[Proof Bundle + Response Hash]
    D --> E[Dowsure / Coordinator]
    E --> F[Java Nitro Enclave]
    F --> G[Raw Source Hash]
    F --> H[Deterministic Transformation]
    H --> I[Transformed Hash]
    F --> J[Ephemeral P-256 Key]
    J --> K[AWS Nitro Attestation]
    K --> L[PCR / Certificate / Root Validation]
    L --> M[Olea Verifier]
    M --> N[Evidence Vault / Receipt]

    style C fill:#f9d423,stroke:#333,stroke-width:1px
    style L fill:#8ad17d,stroke:#333,stroke-width:1px
    style N fill:#7ab8ff,stroke:#333,stroke-width:1px
```

## What the diagram means

- The source endpoint is an upstream system that may be validated with a proof mechanism.
- The TLSNotary stage is the critical missing dependency in the current PoC.
- The Dowsure coordinator passes the request and proof to the enclave.
- The enclave computes the raw hash, transforms the payload, and binds request metadata into the attestation user_data.
- AWS Nitro produces a signed attestation document.
- Olea verifies the attestation document, PCRs, certificate chain, and key bindings.
- If the proof and attestation both pass, the evidence is retained and a receipt is produced.

## Current reality

At the moment, the lower trust path is working:

- Nitro enclave runtime,
- attestation verification,
- PCR validation,
- hash binding,
- EIF registration.

The missing upper path is the real source-proof gate:

- approved TLSNotary prover,
- approved notary key,
- compatible endpoint,
- signed proof bundle.

Until that exists, the flow remains intentionally fail-closed.
