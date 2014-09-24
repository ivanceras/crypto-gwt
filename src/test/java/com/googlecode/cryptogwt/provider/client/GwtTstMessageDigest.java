package com.googlecode.cryptogwt.provider.client;

import java.util.Iterator;

import com.google.gwt.user.client.DeferredCommand;
import com.google.gwt.user.client.IncrementalCommand;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import com.googlecode.cryptogwt.provider.CryptoGwtProvider;
import com.googlecode.cryptogwt.tests.CryptoTestVector;
import com.googlecode.cryptogwt.tests.MessageDigestTestVectors;
import static com.googlecode.cryptogwt.tests.CryptoTestVectors.*;

public class GwtTstMessageDigest extends CryptoGwtProviderGWTTestCase {
    
    public void testHaveTestVectors() {
        assertTrue(MessageDigestTestVectors.INSTANCE.getAlgorithms().size() > 0);
    }
    
    public static interface DigestStrategy {
        byte[] digest(MessageDigest md, byte[] input) throws DigestException;
    }
    
    class DigestTestRunner implements IncrementalCommand {
        private DigestStrategy strategy;
        
        private Iterator<String> algorithms = MessageDigestTestVectors.INSTANCE.getAlgorithms().iterator();
        private Iterator<CryptoTestVector> testVector = null;        
        private MessageDigest digest;
        private String description;
        private long started;

        public DigestTestRunner(String description, DigestStrategy strategy) {
            this.strategy = strategy;
            this.description = description;
            this.started = System.currentTimeMillis();
        }

        public boolean execute() {
            if (testVector == null || !testVector.hasNext()) {
                if (!algorithms.hasNext()) {
                    finish();
                    return false;
                }
                try {                    
                    final String algorithm = algorithms.next();
                    digest = MessageDigest.getInstance(algorithm);
                    testVector = MessageDigestTestVectors.INSTANCE.get(algorithm).iterator();
                } catch (Exception e) {
                    AssertionError assertFailed = new AssertionError("Unexpected exception");
                    assertFailed.initCause(e);
                    throw assertFailed;
                }
            }
            
            CryptoTestVector vector = testVector.next();
            try {
                assertOutputEquals(vector, 
                        strategy.digest(digest, vector.input));
            } catch (DigestException e) {
                AssertionError assertFailed = new AssertionError("Unexpected exception");
                assertFailed.initCause(e);
                throw assertFailed;
            }
            return true;
        }

        private void finish() {            
            finishTest();
        }
    }
    
        
    public void testCanPassTestVectorsForOneCallDigest() throws GeneralSecurityException {        
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        DeferredCommand.addCommand(new DigestTestRunner(
                "testCanPassTestVectorsForOneCallDigest",
                new DigestStrategy() {           
            public byte[] digest(MessageDigest md, byte[] input) throws DigestException {
                return md.digest(input);
            }
        }));
        delayTestFinish(10000);
    }
    
    public void testCanPassTestVectorsWhenUpdatingOneByteAtATime() throws GeneralSecurityException {
        
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        DeferredCommand.addCommand(new DigestTestRunner(
                "testCanPassTestVectorsWhenUpdatingOneByteAtATime",
                new DigestStrategy() {           
            public byte[] digest(MessageDigest md, byte[] input) throws DigestException {
                for (byte b : input) {
                    md.update(new byte[] { b });
                }
                return md.digest();
            }
        }));
        delayTestFinish(10000);
    }
    
    public void testNistSHA256ExampleMutlipleBlocks() throws Exception {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] m = asciiToBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"); 
        md.digest(m);
        assertOutputEquals("248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",
                md.digest(m));
    }

    public void testNistSHA256ExampleSingleBlock() throws Exception {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] m = asciiToBytes("abc");         
        assertOutputEquals("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
                md.digest(m));
    }    
    
    public void testCanPassTestVectorsWhenUpdatingRangeOfBytes() throws GeneralSecurityException {        
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        DeferredCommand.addCommand(new DigestTestRunner(
                "testCanPassTestVectorsWhenUpdatingRangeOfBytes",
                new DigestStrategy() {           
                    public byte[] digest(MessageDigest md, byte[] input) throws DigestException {
                        for (int i=0; i < input.length; i += 4) {
                            if (i + 4 > input.length) {
                                md.update(input, i, input.length-i);
                            } else {
                                md.update(input, i, 4);
                            }
                        }
                        return md.digest();
                    }
                }));
        delayTestFinish(10000);
    }

    public void testCanPassTestVectorsWithSingleDigestAndReset() throws GeneralSecurityException {        
        DeferredCommand.addCommand(new DigestTestRunner(
                "testCanPassTestVectorsWithSingleDigestAndReset",
                new DigestStrategy() {           
            public byte[] digest(MessageDigest md, byte[] input) throws DigestException {
                md.update(new byte[] { 0x1 });
                md.reset();
                return md.digest(input);            
            }
        }));
        delayTestFinish(10000);
    }
    
    public void testDigestAlwaysResetsDigest() throws GeneralSecurityException {        
        DeferredCommand.addCommand(new DigestTestRunner(
                "testDigestAlwaysResetsDigest",
                new DigestStrategy() {           
            public byte[] digest(MessageDigest md, byte[] input) throws DigestException {
                md.digest(new byte[] { 0x1 });
                return md.digest(input);            
            }
        }));
        delayTestFinish(10000);
    }

    public void testCanReturnDigestLength() throws NoSuchAlgorithmException {
        System.out.println("testCanReturnDigestLength");
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            assertEquals((int)MessageDigestTestVectors.INSTANCE.getProperty(algorithm, "digestLength", int.class), 
                    md.getDigestLength());
        }
    }
}