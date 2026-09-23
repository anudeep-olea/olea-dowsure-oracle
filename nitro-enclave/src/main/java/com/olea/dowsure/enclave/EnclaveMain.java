package com.olea.dowsure.enclave;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public final class EnclaveMain {
    private EnclaveMain() {
    }

    public static void main(String[] args) {
        ObjectMapper mapper = new ObjectMapper();
        EnclaveService service = new EnclaveService(mapper, new JnaAttestationProvider());
        try {
            new VsockServer().serve(16, 5005, request -> {
            try {
                Map<String, Object> input = mapper.readValue(request, new TypeReference<>() {
                });
                return mapper.writeValueAsString(Map.of("ok", true, "evidence", service.acquire(input)));
            } catch (Exception error) {
                return mapper.createObjectNode().put("ok", false).put("error", error.getMessage()).toString();
            }
            });
        } catch (Exception error) {
            throw new IllegalStateException("VSOCK_SERVER_FAILED", error);
        }
    }
}
