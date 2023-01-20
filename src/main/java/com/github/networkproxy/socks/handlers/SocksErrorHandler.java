package com.github.networkproxy.socks.handlers;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import com.github.networkproxy.proxy.handlers.Handler;
import com.github.networkproxy.network.Connection;

public final class SocksErrorHandler extends Handler {
    private static final int EMPTY = 0;
    public SocksErrorHandler(Connection connection) {
        super(connection);
    }

    @Override
    public void handle(SelectionKey selectionKey) {
    }

    @Override
    public int write(SelectionKey selectionKey) throws IOException {
        int remaining = super.write(selectionKey);
        if (remaining == EMPTY) {
            SocketChannel socket = (SocketChannel) selectionKey.channel();
            socket.close();
        }
        return remaining;
    }
}
