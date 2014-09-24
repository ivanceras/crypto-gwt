/**
 * 
 */
package com.googlecode.cryptogwttests;

import javax.crypto.CipherSpi;
import com.googlecode.cryptogwt.util.SpiFactory;

public class CipherSpiFactory implements SpiFactory<CipherSpi> {
    private final Class<? extends javax.crypto.CipherSpi> type;
    
    public CipherSpiFactory(Class<? extends javax.crypto.CipherSpi> type) {
        this.type = type;
    }

    public CipherSpi create(Object constructorParam) {
        try {
            return Adaptor.adapt(type.newInstance(), CipherSpi.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid type: " + type, e);
        }
    }
}