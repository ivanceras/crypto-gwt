package com.googlecode.cryptogwttests;

import java.security.MessageDigestSpi;
import com.googlecode.cryptogwt.util.SpiFactory;

public class MessageDigestSpiFactory implements SpiFactory<MessageDigestSpi> {
    private final Class<? extends java.security.MessageDigestSpi> type;
    
    public MessageDigestSpiFactory(Class<? extends java.security.MessageDigestSpi> type) {
        this.type = type;
    }

    public MessageDigestSpi create(Object constructorParam) {
        try {
            return Adaptor.adapt(type.newInstance(), MessageDigestSpi.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid type: " + type, e);
        }
    }
}
