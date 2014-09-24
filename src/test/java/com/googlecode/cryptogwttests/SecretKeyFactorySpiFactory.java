package com.googlecode.cryptogwttests;

import javax.crypto.SecretKeyFactorySpi;
import com.googlecode.cryptogwt.util.SpiFactory;

public class SecretKeyFactorySpiFactory implements SpiFactory<SecretKeyFactorySpi> {

    private Class<? extends javax.crypto.SecretKeyFactorySpi> type;

    public SecretKeyFactorySpiFactory(Class<? extends javax.crypto.SecretKeyFactorySpi> type) {
        this.type = type;
    }

    public SecretKeyFactorySpi create(Object constructorParam) {
        try {
            return Adaptor.adapt(type.newInstance(), SecretKeyFactorySpi.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid type: " + type, e);
        }
    }

}
