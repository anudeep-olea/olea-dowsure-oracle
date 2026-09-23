import argparse
import base64
import hashlib
import json
import socket
import urllib.request
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def post(url, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def canonicalize(value):
    if value is None or isinstance(value, (bool, str, int, float)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + canonicalize(value[key])
            for key in sorted(value)
        ) + "}"
    raise ValueError("NON_CANONICAL_VALUE")


def invoke_enclave(cid, port, request):
    vso_family = getattr(socket, "AF_VSOCK", None)
    if vso_family is None:
        raise RuntimeError("AF_VSOCK_UNAVAILABLE_ON_HOST")

    channel = socket.socket(vso_family, socket.SOCK_STREAM)
    channel.connect((cid, port))
    payload = json.dumps(request).encode()
    channel.sendall(payload)
    channel.shutdown(socket.SHUT_WR)
    result = json.loads(channel.recv(1024 * 1024).decode())
    channel.close()
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "ENCLAVE_FAILED"))
    return result["evidence"]


def sign(private_key_file, value):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return base64.b64encode(private_key.sign(value.encode(), ec.ECDSA(hashes.SHA256()))).decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--olea-url", required=True)
    parser.add_argument("--enclave-cid", type=int, default=16)
    parser.add_argument("--enclave-port", type=int, default=5005)
    parser.add_argument("--raw-payload-file", required=True)
    parser.add_argument("--tls-proof-file", required=True)
    parser.add_argument("--dowsure-private-key-file", required=True)
    parser.add_argument("--eif-digest", required=True)
    args = parser.parse_args()

    request_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    challenge = post(args.olea_url + "/v1/challenges", {
        "requestId": request_id,
        "source": "mock-api",
        "endpoint": "GET_ORDERS",
        "operation": "GET_ORDERS",
        "policyVersion": "v1.0",
    })
    raw_payload = json.load(open(args.raw_payload_file, encoding="utf-8"))
    tls_proof = json.load(open(args.tls_proof_file, encoding="utf-8"))
    evidence = invoke_enclave(args.enclave_cid, args.enclave_port, {
        "requestId": request_id,
        "source": "mock-api",
        "endpoint": "GET_ORDERS",
        "nonce": challenge["nonce"],
        "policyVersion": challenge["policyVersion"],
        "rawPayload": raw_payload,
        "tlsProof": tls_proof,
        "evidenceId": evidence_id,
        "eifDigest": args.eif_digest,
    })
    manifest_digest = evidence["manifestDigest"]
    submitted_at = datetime.now(timezone.utc).isoformat()
    envelope = {
        "requestId": request_id,
        "nonce": challenge["nonce"],
        "policyVersion": challenge["policyVersion"],
        "evidenceId": evidence_id,
        "manifestDigest": manifest_digest,
        "encryptedEvidenceReference": evidence["encryptedEvidenceReference"],
        "submittedAt": submitted_at,
    }
    evidence["submissionEnvelope"] = envelope
    evidence["submissionSignature"] = sign(args.dowsure_private_key_file, canonicalize(envelope))
    print(json.dumps({"requestId": request_id, "evidenceId": evidence_id, "challenge": challenge, "evidence": evidence}, indent=2))


if __name__ == "__main__":
    main()
