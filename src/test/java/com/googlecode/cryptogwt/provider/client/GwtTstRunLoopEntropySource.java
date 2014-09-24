package com.googlecode.cryptogwt.provider.client;

import java.security.Security;
import com.googlecode.cryptogwt.provider.CryptoGwtProvider;
import com.googlecode.cryptogwt.provider.EntropySink;
import com.googlecode.cryptogwt.provider.RunLoopEntropySource;

public class GwtTstRunLoopEntropySource extends CryptoGwtProviderGWTTestCase {
    public void testRunloopEntropySource() {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        RunLoopEntropySource runloop = new RunLoopEntropySource(new EntropySink() {
            int totalEntropy = 0;
            public void addEntropy(int seedId, double estimatedEntropy, byte[] seed) {
                totalEntropy += estimatedEntropy;
                if (totalEntropy  < 128) finishTest();               
            }

            public boolean needsEntropy() {
                return true;
            }

        });
        runloop.startCollecting();
        delayTestFinish(100000);
        
    }
}
