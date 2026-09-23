package com.olea.dowsure.enclave;

public interface AttestationProvider {
    byte[] generateAttestation(byte[] userData, byte[] publicKey);
}
