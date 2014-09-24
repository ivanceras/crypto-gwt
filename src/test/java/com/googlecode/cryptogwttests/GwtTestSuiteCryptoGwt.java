package com.googlecode.cryptogwttests;

import junit.framework.Test;
import junit.framework.TestCase;

import com.google.gwt.junit.tools.GWTTestSuite;
import com.googlecode.cryptogwt.provider.GwtTstPbeSecretKeyFactory;
import com.googlecode.cryptogwt.provider.client.GwtTstCipher;
import com.googlecode.cryptogwt.provider.client.GwtTstEventEntropySource;
import com.googlecode.cryptogwt.provider.client.GwtTstJsArrayUtils;
import com.googlecode.cryptogwt.provider.client.GwtTstMac;
import com.googlecode.cryptogwt.provider.client.GwtTstMessageDigest;
import com.googlecode.cryptogwt.provider.client.GwtTstNistRandomNumberTests;
import com.googlecode.cryptogwt.provider.client.GwtTstRunLoopEntropySource;
import com.googlecode.cryptogwt.provider.client.GwtTstSecureRandom;

public class GwtTestSuiteCryptoGwt extends TestCase {

    public static Test suite() {
        GWTTestSuite suite = new GWTTestSuite("Unit tests for GWT crypto code");        
        suite.addTestSuite(GwtTstCipher.class);
        suite.addTestSuite(GwtTstJsArrayUtils.class);
        suite.addTestSuite(GwtTstMessageDigest.class);
        suite.addTestSuite(GwtTstSecureRandom.class);
        suite.addTestSuite(GwtTstNistRandomNumberTests.class);
        suite.addTestSuite(GwtTstRunLoopEntropySource.class);
        suite.addTestSuite(GwtTstEventEntropySource.class);
        suite.addTestSuite(GwtTstMac.class);
        suite.addTestSuite(GwtTstPbeSecretKeyFactory.class);
        return suite;
    }
}
