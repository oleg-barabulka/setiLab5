package com.github.networkproxy;

import com.github.networkproxy.proxy.Proxy;
import org.apache.log4j.Logger;

public final class Main {
    private static final Logger logger = Logger.getLogger(Main.class);
    private static final int COMMAND_LINE_ARGUMENT_COUNT = 1;
    private static final int MIN_PORT = 1025;
    private static final int MAX_PORT = 65535;

    public static void main(String[] args) {
        if (args.length != COMMAND_LINE_ARGUMENT_COUNT) {
            logger.error("Usage: port");
            return;
        }

        int port;
        try {
            port = Integer.parseInt(args[0]);
            if (!isPortValid(port)) {
                logger.error(String.format("Port is out of range [%d, %d], got %d", MIN_PORT, MAX_PORT, port));
                return;
            }
        }
        catch (NumberFormatException exception) {
            logger.error("Incorrect port format ", exception);
            return;
        }

        Proxy proxy = new Proxy(port);
        proxy.start();
    }

    private static boolean isPortValid(int port) {
        return MIN_PORT <= port && port <= MAX_PORT;
    }
}
