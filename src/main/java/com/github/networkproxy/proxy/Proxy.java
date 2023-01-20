package com.github.networkproxy.proxy;

import com.github.networkproxy.network.Connection;
import com.github.networkproxy.network.DNS;
import com.github.networkproxy.proxy.handlers.AcceptClientHandler;
import com.github.networkproxy.proxy.handlers.Handler;
import lombok.RequiredArgsConstructor;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;

@RequiredArgsConstructor
public final class Proxy {
    private static final Logger logger = Logger.getLogger(Proxy.class);

    private final int port;

    public void start() {
        try (Selector selector = Selector.open();
             ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.bind(new InetSocketAddress(port));
            serverSocketChannel.configureBlocking(false);
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT, new AcceptClientHandler(serverSocketChannel));

            DNS dns = DNS.create();
            dns.register(selector);

            run(selector);
        }
        catch (IOException exception) {
            logger.error(exception);
        }
    }

    private void run(Selector selector) throws IOException {
        while (true) {
            selector.select();
            Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
            while (iterator.hasNext()) {
                SelectionKey readyKey = iterator.next();
                iterator.remove();
                try {
                    if (readyKey.isValid()) {
                        handleSelectionKey(readyKey);
                    }
                }
                catch (IOException exception) {
                    exception.printStackTrace();
                    logger.error(exception);
                    closeConnection(readyKey);
                }
            }
        }
    }

    private void handleSelectionKey(SelectionKey selectionKey) throws IOException {
        Handler handler = (Handler) selectionKey.attachment();
        if (selectionKey.isWritable()) {
            handler.write(selectionKey);
        }
        else {
            handler.handle(selectionKey);
        }
    }

    private void closeConnection(SelectionKey selectionKey) throws IOException {
        Handler handler = (Handler) selectionKey.attachment();
        Connection connection = handler.getConnection();
        SocketChannel socketChannel = (SocketChannel) selectionKey.channel();

        try {
            logger.debug("Socket closed: " + socketChannel.getRemoteAddress());
            socketChannel.close();
            connection.closeChannel();
        }
        catch (ClosedChannelException exception) {
            logger.error(exception);
        }
    }
}
