package com.olea.dowsure.enclave;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

import java.util.Arrays;

public final class JnaAttestationProvider implements AttestationProvider {
    interface NativeNsm extends Library {
        NativeNsm INSTANCE = Native.load("nsm", NativeNsm.class);
        int nsm_lib_init();
        void nsm_lib_exit(int fd);
        int nsm_get_attestation_doc(int fd, byte[] userData, int userDataLength, byte[] nonce, int nonceLength, byte[] publicKey, int publicKeyLength, byte[] document, IntByReference documentLength);
    }

    @Override
    public byte[] generateAttestation(byte[] userData, byte[] publicKey) {
        int fd = NativeNsm.INSTANCE.nsm_lib_init();
        if (fd < 0) throw new IllegalStateException("NSM_OPEN_FAILED");
        byte[] document = new byte[16 * 1024];
        IntByReference documentLength = new IntByReference(document.length);
        try {
            int status = NativeNsm.INSTANCE.nsm_get_attestation_doc(fd, userData, userData.length, null, 0, publicKey, publicKey.length, document, documentLength);
            if (status != 0) throw new IllegalStateException("NSM_ATTESTATION_FAILED:" + status);
            return Arrays.copyOf(document, documentLength.getValue());
        } finally {
            NativeNsm.INSTANCE.nsm_lib_exit(fd);
        }
    }
}
