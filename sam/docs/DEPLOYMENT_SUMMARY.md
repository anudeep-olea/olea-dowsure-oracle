# Deployment Summary

- **Deployment Model: Real [[Olea]], Real [[AWS Nitro Enclave]], Mock [[Dowsure]] orchestration, and Mock Source API**
  - Validate and build Olea:
    - `sam validate --lint --template-file olea/template.yaml`
    - `sam build --template-file olea/template.yaml --build-dir olea/.aws-sam/build`
  - Deploy Olea with an explicit approved profile:
    - `sam deploy --guided --template-file olea/.aws-sam/build/template.yaml --profile preprod --region ap-southeast-1`
  - Record the Olea `ApiUrl` output.
  - Supply `NitroRootCertPem` with the AWS Nitro root certificate PEM when deploying Olea; an empty value intentionally causes attestation verification to fail closed.
  - Register policy `v1.0` through `POST /v1/policies`.
  - Register the approved EIF digest and live PCR0/PCR1/PCR2 values through `POST /v1/releases` for the `GET_ORDERS` source-proof flow.
  - Deploy Dowsure, passing the Olea output:
    - `sam deploy --guided --template-file dowsure/template.yaml --parameter-overrides OleaApiBaseUrl=<OLEA_API_URL> --profile preprod --region ap-southeast-1`
  - Configure the approved mock source `GET /orders` endpoint and TLSNotary proof in the enclave runtime for Phase 1.
  - Do not deploy or configure Amazon SP-API, LWA, seller accounts, reports, or financial-report fixtures in Phase 1.

- **Stack Independence**
  - Each directory is an independent SAM application.
  - No stack imports or exports are required.
  - Endpoint URLs are explicit deployment parameters.
  - The mock source can be replaced independently without changing the Olea control plane.

- **Nitro PoC Runtime**
  - Template: [../../infra/nitro-ec2.yaml](../../infra/nitro-ec2.yaml)
  - Stack: `olea-dowsure-nitro-preprod`
  - Host: `i-0b2b6aa26fb920103`, `c5.xlarge`, private subnet, SSM-managed, no SSH ingress.
  - Enclave: `olea-orders`, CID `16`, `2048 MiB`, `2` vCPUs, EIF state `RUNNING`.
  - The stack uses a two-phase deployment: create support resources with `LaunchHost=false`, upload the context, then update with `LaunchHost=true`.
  - Publish context from the repository root: `& .\scripts\publish-nitro-artifact.ps1 -Profile preprod -Region ap-southeast-1 -StackName olea-dowsure-nitro-preprod`
  - The host builds the EIF with `NITRO_CLI_ARTIFACTS=/var/lib/nitro_enclaves` and starts it through `nitro-cli`.

- **Verified PoC Evidence**
  - Olea stack: `UPDATE_COMPLETE`.
  - Direct signed evidence test: policy `201`, release `201`, challenge `201`, evidence `202 ACCEPTED`.
  - Evidence vault object was written with KMS encryption.
  - The PoC release uses the live EIF PCR0/PCR1/PCR2 values and generated ECDSA keys.

- **Java Enclave Phase 4 — EIF and Runtime Verified (2026-09-23)**
  - The current Docker builder compiles the shaded Java 21 JAR, compiles the pinned NSM library, and uses the Java runtime image with `java -jar /app/enclave-service.jar`.
  - Host image: `olea-nitro-orders:java-phase4`; image ID `5c7f299e46ffe90d8e2fadb0bb0808a7a171512cc84b6f3eb0d0de2d91f88ab3`.
  - EIF: `/opt/olea-nitro/olea-orders-java-phase4.eif`, `464095310` bytes, `EifVersion 4`, `CheckCRC true`, `IsSigned false`.
  - EIF measurements: PCR0 `5fba63399c819c8658452d9d48f35ecd491f9d65d5d842eb7ada4ae23a63cb666796a643102c9cc9e71c8a4bc60baba9`; PCR1 `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`; PCR2 `6560ff543ea448942b3f50ebadf606223a7aed1120856b503468a127671b22de6cbf195e0beb423b255100349e22c68f`.
  - The enclave is running as `olea-orders-java`, CID `16`, with `2` vCPUs and `2048 MiB`. CID `16` is required because `EnclaveMain` currently binds Java AF_VSOCK port `5005` to CID `16`.
  - A CID `17` launch correctly exposed the mismatch as `VSOCK_SERVER_FAILED`; it was not an EIF failure. The corrected CID `16` launch reaches `RUNNING`.
  - The old Python EIF/PCR set must not be used as Java evidence. The Java phase4 EIF was restarted without `--debug-mode`; `describe-enclaves` reports `Flags: NONE` and the measurements match the phase4 baseline.
  - Live evidence request `293548c9-9975-4cc0-9039-b19a5ce6b421` / evidence `e826e531-cbc6-41ed-93d5-1da3ae68fe09` passed AWS Nitro Root-G1, COSE, certificate-chain, PCR, public-key, and canonicalized user-data verification.
  - The exact phase4 EIF SHA-256 `246e2143aeecb6c2e4f5e551536b2dfc75e8313fd521dd4da91da8f5d907da94` is registered `ACTIVE` in the preprod Olea release registry.
  - Remaining gates: run the live Olea acceptance receipt and replace the TLSNotary proof contract with an approved prover/notary service and real signed proof verification.

- **Suggested Stack Names**
  - `olea-oracle-preprod`
  - `dowsure-oracle-preprod`
  - `olea-source-proof-mock`

- **Teardown Warning**
  - The real Olea stack retains KMS keys, DynamoDB tables, and the Object Lock bucket.
  - Object Lock COMPLIANCE objects cannot be deleted before retention expires.
  - Mock stacks contain no retained data stores.
