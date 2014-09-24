package com.googlecode.cryptogwttests;


import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.googlecode.cryptogwt.tests.CryptoTestVector;
import com.googlecode.cryptogwt.tests.MessageDigestTestVectors;

import static org.junit.Assert.*;

import static com.googlecode.cryptogwt.tests.CryptoTestVectors.*;

public class MessageDigestTest {
    
    @BeforeClass
    public static void setUp() {
        Security.addProvider(JceAdaptorProvider.getInstance());
    }
    
    @Test
    public void haveTestVectors() {
        assertTrue(MessageDigestTestVectors.INSTANCE.getAlgorithms().size() > 0);
    }
    
    @Test(expected=NoSuchAlgorithmException.class)
    public void throwsExceptionOnBogusDigestAlgorithm() throws NoSuchAlgorithmException {
        MessageDigest.getInstance("Bogus Digest Algorithm");
    }
    
    @Test
    public void canCreateSupportedDigests() throws NoSuchAlgorithmException {
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            assertNotNull(md);
        }
    }
    
    @Test
    public void canPassTestVectorsForOneCallDigest() throws GeneralSecurityException {
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : MessageDigestTestVectors.INSTANCE.get(algorithm)) {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                assertOutputEquals(vector.expectedOutput, md.digest(vector.input));            
            }
        }
    }
    
    @Test
    public void canPassTestVectorsWhenUpdatingOneByteAtATime() throws GeneralSecurityException {        
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : MessageDigestTestVectors.INSTANCE.get(algorithm)) {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                for (byte b : vector.input) {
                    md.update(new byte[] { b });
                }
                assertOutputEquals(vector.expectedOutput, md.digest());

            }
        }
    }
    
    @Test
    public void canPassTestVectorsWhenUpdatingRangeOfBytes() throws GeneralSecurityException {        
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : MessageDigestTestVectors.INSTANCE.get(algorithm)) {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                for (int i=0; i < vector.input.length; i += 4) {
                    if (i + 4 > vector.input.length) {
                        md.update(vector.input, i, vector.input.length-i);
                    } else {
                        md.update(vector.input, i, 4);
                    }
                }
                assertOutputEquals(vector.expectedOutput, md.digest());

            }
        }
    }
    
    @Test
    public void canPassTestVectorsWithSingleDigestAndReset() throws GeneralSecurityException {
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            for (CryptoTestVector vector : MessageDigestTestVectors.INSTANCE.get(algorithm)) {
                md.reset();
                assertOutputEquals(vector.expectedOutput, md.digest(vector.input));            
            }
        }
    }
    
    @Test
    public void canReturnDigestLength() throws NoSuchAlgorithmException {
        for (String algorithm : MessageDigestTestVectors.INSTANCE.getAlgorithms()) {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            assertEquals((int)MessageDigestTestVectors.INSTANCE.getProperty(algorithm, "digestLength", int.class), 
                    md.getDigestLength());
        }
    }

    @Test
    public void testNistSHA256ExampleMutlipleBlocks() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] m = asciiToBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"); 
        md.digest(m);
        assertOutputEquals("248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",
                md.digest(m));
    }

    @Test
    public void testNistSHA256ExampleSingleBlock() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] m = asciiToBytes("abc"); 
        
        assertOutputEquals("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
                md.digest(m));
    }

    @Test
    public void testNistSHA256ExampleLongMessage() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 1000000; i++) {
            md.update((byte)('a' & 0xff));
        }        
        assertOutputEquals("cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0",
                md.digest());
    }
    
    @Ignore // Use this to generate monte carlo tests    
    public void generateRandomTestVectors() throws GeneralSecurityException, java.security.NoSuchAlgorithmException {
        final int NUMBER_OF_TESTS = 1;
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");
        int[] inputSizes = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 32, 31, 64, 65 };
        for (String algorithm : new String[] { "SHA1", "SHA-256" }) {
           
            for (int inputSize : inputSizes) {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                for (int i=0; i < NUMBER_OF_TESTS; i++) {
                    byte[] input = new byte[inputSize];
                    random.nextBytes(input);
                    byte[] output = md.digest(input);
                    System.out.println("// Test#" + i + " for input of " + inputSize + " bytes");
                    System.out.println("add(\"" + algorithm + "\","); 
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(input) + "\"),");                    
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(output) + "\"));\n");
                }

            }
        }
    }

}
