package com.googlecode.cryptogwttests;

import java.security.SecureRandomSpi;
import com.googlecode.cryptogwt.util.SpiFactory;

public class SecureRandomSpiFactory implements SpiFactory<SecureRandomSpi> {

    private Class<? extends java.security.SecureRandomSpi> type;

    public SecureRandomSpiFactory(Class<? extends java.security.SecureRandomSpi> type) {
        this.type = type;
    }

    public SecureRandomSpi create(Object constructorParam) {
        try {
            return Adaptor.adapt(type.newInstance(), SecureRandomSpi.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid type: " + type, e);
        }
    }

}
