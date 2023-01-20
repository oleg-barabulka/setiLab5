package com.github.networkproxy.socks;

import com.github.networkproxy.socks.message.SocksConnectRequest;
import com.github.networkproxy.socks.message.SocksRequest;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public final class SocksParser {
    private static final byte ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
    private static final byte COMMAND_NOT_SUPPORTED = 0x07;
    private static final int IPV4 = 0x01;
    private static final int DOMAIN_NAME = 0x03;
    private static final int CONNECT_COMMAND = 0x01;

    public static SocksConnectRequest parseConnectRequest(ByteBuffer byteBuffer) {
        try {
            byteBuffer.flip();
            SocksConnectRequest socksRequest = new SocksConnectRequest();
            socksRequest.setVersion(byteBuffer.get());
            socksRequest.setNumOfMethods(byteBuffer.get());
            byteBuffer.get(socksRequest.getAuthenticationMethods());
            return socksRequest;
        }
        catch (BufferUnderflowException exception) {
            prepareBufferToWrite(byteBuffer);
            return null;
        }
    }

    public static SocksRequest parseRequest(ByteBuffer byteBuffer) {
        try {
            SocksRequest request = new SocksRequest();
            byteBuffer.flip();
            request.setVersion(byteBuffer.get());
            byte command = byteBuffer.get();

            if (command != CONNECT_COMMAND) {
                request.setRsv(COMMAND_NOT_SUPPORTED);
            }

            request.setCommandCode(command);
            byteBuffer.get();
            setAddressType(byteBuffer.get(), byteBuffer, request);
            request.setDestinationPort(byteBuffer.getShort());
            return request;
        }
        catch (BufferUnderflowException exception) {
            prepareBufferToWrite(byteBuffer);
            return null;
        }
    }

    private static void prepareBufferToWrite(ByteBuffer byteBuffer) {
        int newStartPos = byteBuffer.limit();
        byteBuffer.clear();
        byteBuffer.position(newStartPos);
    }

    private static void setAddressType(byte addressType, ByteBuffer byteBuffer, SocksRequest request) {
        request.setAddressType(addressType);
        switch (addressType) {
            case IPV4 -> byteBuffer.get(request.getIp4Address());
            case DOMAIN_NAME -> request.setDomainName(getDomainName(byteBuffer));
            default -> request.setRsv(ADDRESS_TYPE_NOT_SUPPORTED);
        }
    }

    private static String getDomainName(ByteBuffer byteBuffer) {
        byte nameLength = byteBuffer.get();
        byte[] nameBytes = new byte[nameLength];
        byteBuffer.get(nameBytes);
        return new String(nameBytes, StandardCharsets.UTF_8);
    }
}