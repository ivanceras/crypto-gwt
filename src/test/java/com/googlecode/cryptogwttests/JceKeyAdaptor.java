package com.googlecode.cryptogwttests;

import java.security.Key;

public class JceKeyAdaptor implements Key {

    private static final long serialVersionUID = -1359994722999041821L;

    private java.security.Key delegate;
    
    public JceKeyAdaptor(java.security.Key key) {
        this.delegate = key;
    }

    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    public byte[] getEncoded() {
        return delegate.getEncoded();
    }

    public String getFormat() {
        return delegate.getFormat();
    }

}
