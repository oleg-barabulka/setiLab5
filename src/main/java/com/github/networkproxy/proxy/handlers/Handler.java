package com.github.networkproxy.proxy.handlers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import com.github.networkproxy.network.Connection;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.log4j.Logger;

@RequiredArgsConstructor
public abstract class Handler {
    private final static double LOAD_FACTOR = 0.75;
    private final static int EMPTY = 0;
    private static final Logger logger = Logger.getLogger(Handler.class);
    private static final int BUF_SIZE = 65536;

    @Getter private final Connection connection;

    public abstract void handle(SelectionKey selectionKey) throws IOException;

    public static int getBufSize() {
        return BUF_SIZE;
    }

    public int read(SelectionKey selectionKey) throws IOException {
        Handler handler = (Handler) selectionKey.attachment();
        SocketChannel socket = (SocketChannel) selectionKey.channel();
        ByteBuffer outputBuffer = handler.getConnection().getOutputBuffer().getByteBuffer();

        int readCount = socket.read(outputBuffer);
        if (readCount <= 0) {
            connection.shutdown();
            selectionKey.interestOps(EMPTY);
            if (connection.isReadyToClose()) {
                closeConnection(socket);
            }
        }

        if (outputBuffer.position() > BUF_SIZE * LOAD_FACTOR) {
            selectionKey.interestOpsAnd(~SelectionKey.OP_READ);
        }

        return readCount;
    }

    public int write(SelectionKey selectionKey) throws IOException {
        ByteBuffer inputBuffer = connection.getInputBuffer().getByteBuffer();
        SocketChannel socketChannel = (SocketChannel) selectionKey.channel();
        connection.prepareToWrite();
        socketChannel.write(inputBuffer);
        int remaining = inputBuffer.remaining();
        if (inputBuffer.position() > BUF_SIZE * LOAD_FACTOR) selectionKey.interestOpsOr(SelectionKey.OP_READ);

        if (remaining == EMPTY) {
            selectionKey.interestOps(SelectionKey.OP_READ);
            checkChannel(socketChannel, inputBuffer);
        }
        else {
            connection.shiftWriteStartPosition();
        }
        return remaining;
    }

    private void closeConnection(SocketChannel socketChannel) throws IOException {
        logger.debug("Socket closed: " + socketChannel.getRemoteAddress());
        socketChannel.close();
        connection.closeChannel();
    }

    private void checkChannel(SocketChannel socketChannel, ByteBuffer buffer) throws IOException {
        if (connection.isShutdown()) {
            socketChannel.shutdownOutput();
            return;
        }

        buffer.clear();
        connection.resetWriteStartPosition();
    }
}
