package com.googlecode.cryptogwt.provider.client;

import com.google.gwt.junit.client.GWTTestCase;

public abstract class CryptoGwtProviderGWTTestCase extends GWTTestCase {
    @Override
    public String getModuleName() {
        return "com.googlecode.cryptogwt.Tests";
    }
}
