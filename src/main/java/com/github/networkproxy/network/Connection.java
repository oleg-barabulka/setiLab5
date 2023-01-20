package com.github.networkproxy.network;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

@RequiredArgsConstructor
public final class Connection {
    private static final Logger logger = Logger.getLogger(Connection.class);

    @Getter private final ByteBufferWrapper inputBuffer;
    @Getter private final ByteBufferWrapper outputBuffer;

    @Setter private SocketChannel channel;
    private int writeStartPosition = 0;

    public Connection(int bufSize) {
        this.inputBuffer = new ByteBufferWrapper(ByteBuffer.allocate(bufSize));
        this.outputBuffer = new ByteBufferWrapper(ByteBuffer.allocate(bufSize));
    }

    public void registerChanger(Runnable changer) {
        inputBuffer.setChanger(changer);
    }

    public void changeState() {
        outputBuffer.changeState();
    }

    public void closeChannel() throws IOException {
        if (channel != null) {
            logger.debug("Socket closed: " + channel.getRemoteAddress());
            channel.close();
        }
    }

    public void shutdown() {
        outputBuffer.setClose(true);
    }

    public boolean isShutdown() {
        return inputBuffer.isReadyClose();
    }

    public void prepareToWrite() {
        getInputBuffer().getByteBuffer().flip().position(writeStartPosition);
    }

    public boolean isReadyToClose() {
        return inputBuffer.isReadyClose() && outputBuffer.isReadyClose();
    }

    public void resetWriteStartPosition() {
        writeStartPosition = 0;
    }

    public void shiftWriteStartPosition() {
        ByteBuffer inputBuffer = getInputBuffer().getByteBuffer();
        inputBuffer.compact();
    }

    @RequiredArgsConstructor
    public static final class ByteBufferWrapper {
        @Getter private final ByteBuffer byteBuffer;
        @Setter private Runnable changer;
        @Setter private boolean isClose = false;

        public void changeState(){
            changer.run();
        }

        public boolean isReadyClose(){
            return isClose && (byteBuffer.remaining() == 0);
        }
    }
}
