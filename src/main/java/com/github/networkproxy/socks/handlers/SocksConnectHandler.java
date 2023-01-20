package com.github.networkproxy.socks.handlers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;

import com.github.networkproxy.network.Connection;
import com.github.networkproxy.proxy.handlers.Handler;
import com.github.networkproxy.socks.SocksParser;
import com.github.networkproxy.socks.message.SocksConnectRequest;
import com.github.networkproxy.socks.message.SocksConnectResponse;

public final class SocksConnectHandler extends Handler {
    private static final byte NO_AUTHENTICATION = 0x00;
    private static final int SOCKS_VERSION = 0x05;
    private static final byte NO_COMPARABLE_METHOD = (byte) 0xFF;

    public SocksConnectHandler(Connection connection) {
        super(connection);
    }

    @Override
    public void handle(SelectionKey selectionKey) throws IOException {
        Connection connection = getConnection();
        read(selectionKey);
        ByteBuffer outputBuffer = connection.getOutputBuffer().getByteBuffer();
        SocksConnectRequest connectRequest = SocksParser.parseConnectRequest(outputBuffer);
        if (connectRequest == null) return;

        SocksConnectResponse connectResponse = new SocksConnectResponse();
        if (!isCorrectRequest(connectRequest)) {
            connectResponse.setChosenAuthenticationMethod(NO_COMPARABLE_METHOD);
        }

        ByteBuffer inputBuffer = connection.getInputBuffer().getByteBuffer();
        inputBuffer.put(connectResponse.toByteArray());
        selectionKey.interestOpsOr(SelectionKey.OP_WRITE);
        selectionKey.attach(new SocksRequestHandler(connection));
        connection.getOutputBuffer().getByteBuffer().clear();
    }

    private boolean isCorrectRequest(SocksConnectRequest connectRequest) {
        return (connectRequest.getVersion() == SOCKS_VERSION) && checkMethods(connectRequest.getAuthenticationMethods());
    }

    private static boolean checkMethods(byte[] methods) {
        for (byte method : methods) {
            if (method == NO_AUTHENTICATION) {
                return true;
            }
        }
        return false;
    }
}
