package com.olea.dowsure.enclave;

import org.newsclub.net.unix.vsock.AFVSOCKServerSocket;
import org.newsclub.net.unix.AFVSOCKSocketAddress;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class VsockServer {
    @FunctionalInterface
    public interface RequestHandler {
        String handle(String request);
    }

    public void serve(int cid, int port, RequestHandler handler) throws IOException {
        try (AFVSOCKServerSocket server = AFVSOCKServerSocket.bindOn(AFVSOCKSocketAddress.ofPortAndCID(port, cid))) {
            while (true) {
                try (var socket = server.accept()) {
                    byte[] request = socket.getInputStream().readNBytes(1024 * 1024);
                    byte[] response = handler.handle(new String(request, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
                    socket.getOutputStream().write(response);
                    socket.getOutputStream().flush();
                }
            }
        }
    }
}