package com.github.networkproxy.proxy.handlers;

import java.io.IOException;
import java.nio.channels.SelectionKey;

import com.github.networkproxy.network.Connection;

public final class CommunicationHandler extends Handler {
    public CommunicationHandler(Connection connection) {
        super(connection);
    }

    @Override
    public void handle(SelectionKey selectionKey) throws IOException {
        Connection connection = ((Handler) selectionKey.attachment()).getConnection();
        int readCount = read(selectionKey);
        if (readCount != 0) {
            connection.changeState();
        }
    }
}
