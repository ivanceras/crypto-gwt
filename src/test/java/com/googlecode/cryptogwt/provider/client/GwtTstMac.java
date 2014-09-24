package com.googlecode.cryptogwt.provider.client;



import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.googlecode.cryptogwt.tests.CryptoTestVector;
import com.googlecode.cryptogwt.tests.MacTestVectors;
import com.googlecode.cryptogwttests.GwtTestSuiteCryptoGwt;

import static com.googlecode.cryptogwt.tests.CryptoTestVectors.assertOutputEquals;

public class GwtTstMac extends CryptoGwtProviderGWTTestCase {
    
    public void testHaveTestVectors() {
        assertTrue(MacTestVectors.INSTANCE.getAlgorithms().size() > 0);
    }
        
    public void testCanCreateSupportedMacs() throws NoSuchAlgorithmException {
        for (String algorithm : MacTestVectors.INSTANCE.getAlgorithms()) {
            Mac md = Mac.getInstance(algorithm);
            assertNotNull(md);
        }
    }
    
    public void testCanPassTestVectorsForOneCallMac() throws GeneralSecurityException {
        for (String algorithm : MacTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : MacTestVectors.INSTANCE.get(algorithm)) {
                SecretKeySpec skeySpec = new SecretKeySpec(vector.key, algorithm);
                Mac mac = Mac.getInstance(algorithm);
                mac.init(skeySpec);
                assertOutputEquals(vector.expectedOutput, mac.doFinal(vector.input));            
            }
        }
    }
    
    public void testCanPassTestVectorsWhenUpdatingOneByteAtATime() throws GeneralSecurityException {        
        for (String algorithm : MacTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : MacTestVectors.INSTANCE.get(algorithm)) {
                Mac mac = Mac.getInstance(algorithm);
                SecretKeySpec skeySpec = new SecretKeySpec(vector.key, algorithm);
                mac.init(skeySpec);
                for (byte b : vector.input) {
                    mac.update(b);
                }
                assertOutputEquals(vector.expectedOutput, mac.doFinal());

            }
        }
    }
    
    public void testCanPassTestVectorsWhenUpdatingRangeOfBytes() throws GeneralSecurityException {        
        for (String algorithm : MacTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : MacTestVectors.INSTANCE.get(algorithm)) {
                Mac mac = Mac.getInstance(algorithm);
                SecretKeySpec skeySpec = new SecretKeySpec(vector.key, algorithm);
                mac.init(skeySpec);
                for (int i=0; i < vector.input.length; i += 4) {
                    if (i + 4 > vector.input.length) {
                        mac.update(vector.input, i, vector.input.length-i);
                    } else {
                        mac.update(vector.input, i, 4);
                    }
                }
                assertOutputEquals(vector.expectedOutput, mac.doFinal());

            }
        }
    }
    
    public void testCanPassTestVectorsWithSingleMacAndReset() throws GeneralSecurityException {
        for (String algorithm : MacTestVectors.INSTANCE.getAlgorithms()) {
            Mac mac = Mac.getInstance(algorithm);
            for (CryptoTestVector vector : MacTestVectors.INSTANCE.get(algorithm)) {
                SecretKeySpec skeySpec = new SecretKeySpec(vector.key, algorithm);
                mac.init(skeySpec);
                assertOutputEquals(vector.expectedOutput, mac.doFinal(vector.input));
                mac.reset();
                assertOutputEquals(vector.expectedOutput, mac.doFinal(vector.input));            
            }
        }
    }
    
    public void testCanReturnMacLength() throws NoSuchAlgorithmException {
        for (String algorithm : MacTestVectors.INSTANCE.getAlgorithms()) {
            Mac mac = Mac.getInstance(algorithm);
            assertEquals((int)MacTestVectors.INSTANCE.getProperty(algorithm, "macLength", int.class), 
                    mac.getMacLength());
        }
    }

}
