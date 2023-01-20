package com.github.networkproxy.network;

import com.github.networkproxy.proxy.handlers.ConnectServerHandler;
import com.github.networkproxy.proxy.handlers.Handler;
import com.github.networkproxy.socks.handlers.SocksRequestHandler;
import com.github.networkproxy.socks.message.SocksRequest;
import org.apache.log4j.Logger;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DNS {
    private static final Logger logger = Logger.getLogger(DNS.class);

    private static final int QUERY = 0;
    private static final String DOMAIN_NAME_END = ".";
    private static final byte HOST_UNREACHABLE_ERROR = 0x04;
    private static final int DNS_SERVER_PORT = 53;
    private static final int BUFFER_SIZE = 1024;
    private static final int CACHE_SIZE = 256;

    private static DNS INSTANCE;

    private final Map<Integer, Information> unresolvedNames = new HashMap<>();
    private final Cache resolvedNamesCache = new Cache(CACHE_SIZE);
    private final InetSocketAddress dnsServerAddress;

    private Handler dnsResponseHandler;
    private final DatagramChannel datagramChannel;
    private int messageID = 0;

    public static DNS create() throws IOException {
        if (INSTANCE == null) {
            INSTANCE = new DNS();
        }
        return INSTANCE;
    }

    private DNS() throws IOException {
        DatagramChannel dnsChannel = DatagramChannel.open();
        dnsChannel.configureBlocking(false);
        initResponseHandler();
        this.datagramChannel = dnsChannel;
        this.dnsServerAddress = new InetSocketAddress(ResolverConfig.getCurrentConfig().server().getAddress(), DNS_SERVER_PORT);
    }

    public void register(Selector selector) throws ClosedChannelException {
        this.datagramChannel.register(selector, SelectionKey.OP_READ, dnsResponseHandler);
    }

    public void resolveName(SocksRequest request, SelectionKey selectionKey) throws IOException {
        try {
            String name = request.getDomainName();
            String ip = resolvedNamesCache.get(name + DOMAIN_NAME_END);

            if (ip != null) {
                connectToServer(ip, request.getDestinationPort(), selectionKey);
                return;
            }

            logger.info("New domain name to resolve: " + request.getDomainName());
            Message query = getQuery(name);
            Information info = new Information(selectionKey, request.getDestinationPort());
            unresolvedNames.put(query.getHeader().getID(), info);
            datagramChannel.send(ByteBuffer.wrap(query.toWire()), dnsServerAddress);
        }
        catch (TextParseException exception) {
            SocksRequestHandler.error(selectionKey, HOST_UNREACHABLE_ERROR);
            logger.error(exception);
        }
    }

    private void initResponseHandler() {
        this.dnsResponseHandler = new Handler(null) {
            @Override
            public void handle(SelectionKey selectionKey) throws IOException {
                ByteBuffer byteBuffer = ByteBuffer.allocate(BUFFER_SIZE);
                if (datagramChannel.receive(byteBuffer) == null) {
                    return;
                }

                Message response = new Message(byteBuffer.flip().array());
                List<Record> answers = response.getSection(Section.ANSWER);
                Information unresolvedName = unresolvedNames.get(response.getHeader().getID());

                if (answers.size() == 0) {
                    SocksRequestHandler.error(unresolvedName.selectionKey(), HOST_UNREACHABLE_ERROR);
                    return;
                }

                String hostname = response.getQuestion().getName().toString();
                logger.debug(hostname + " resolved");
                String address = answers.get(0).rdataToString();
                resolvedNamesCache.put(hostname, address);
                connectToServer(address, unresolvedName.port(), unresolvedName.selectionKey());
                int responseID = response.getHeader().getID();
                unresolvedNames.remove(responseID);
            }
        };
    }

    private void connectToServer(String address, int port, SelectionKey selectionKey) throws IOException {
        InetSocketAddress socketAddress = new InetSocketAddress(address, port);
        ConnectServerHandler.connectToServer(selectionKey, socketAddress);
    }

    private Message getQuery(String domainName) throws TextParseException {
        Header header = new Header(messageID++);
        header.setFlag(Flags.RD);
        header.setOpcode(QUERY);

        Message message = new Message();
        message.setHeader(header);

        Record record = Record.newRecord(new Name(domainName + DOMAIN_NAME_END), Type.A, DClass.IN);
        message.addRecord(record, Section.QUESTION);

        return message;
    }

    private record Information(SelectionKey selectionKey, short port) {
    }

    private static final class Cache {
        private final int capacity;
        private final HashMap<String, String> resolvedNames = new HashMap<>(CACHE_SIZE);

        public Cache(int capacity) {
            this.capacity = capacity;
        }

        public String get(String key){
            return resolvedNames.get(key);
        }

        public void put(String key, String value){
            if (resolvedNames.size() >= capacity) {
                resolvedNames.remove(resolvedNames.entrySet().iterator().next().getKey());
            }
            this.resolvedNames.put(key, value);
        }
    }
}