package com.googlecode.cryptogwttests;

import javax.crypto.MacSpi;
import com.googlecode.cryptogwt.util.SpiFactory;

public class MacSpiFactory implements SpiFactory<MacSpi> {
    private final Class<? extends javax.crypto.MacSpi> type;
    
    public MacSpiFactory(Class<? extends javax.crypto.MacSpi> type) {
        this.type = type;
    }

    public MacSpi create(Object constructorParam) {
        try {
            return Adaptor.adapt(type.newInstance(), MacSpi.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid type: " + type, e);
        }
    }
}
