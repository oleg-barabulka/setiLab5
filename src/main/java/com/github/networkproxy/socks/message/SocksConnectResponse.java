package com.github.networkproxy.socks.message;

import lombok.Setter;

public final class SocksConnectResponse {
    private static final byte VERSION = 0x05;

    @Setter private byte chosenAuthenticationMethod = 0x00;

    public byte[] toByteArray() {
        return new byte[] { VERSION, chosenAuthenticationMethod};
    }
}