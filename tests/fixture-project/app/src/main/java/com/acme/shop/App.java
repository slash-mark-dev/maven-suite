package com.acme.shop;

import com.acme.core.Client;
import com.acme.core.Config;
import com.acme.core.Handler;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App implements Handler {
    private static final Logger LOG = LogManager.getLogger(App.class);

    /** A Config subclass: breaks when Config becomes final. */
    static class ShopConfig extends Config {
        ShopConfig() { retries(3); }
    }

    public static void main(String[] args) throws Exception {
        Client c = new Client(new ShopConfig());
        if (c.connect("https://api.acme.example")) {
            LOG.info(c.fetch("/orders"));
        }
        String token = DatatypeConverter.printBase64Binary("secret".getBytes());
        LOG.info(token);
        if (System.getSecurityManager() != null) LOG.info("running under a security manager");
        java.lang.reflect.Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
        LOG.info(f.getName());
        c.close();
    }

    @Override
    public void handle(String event) { LOG.info(event); }
}
