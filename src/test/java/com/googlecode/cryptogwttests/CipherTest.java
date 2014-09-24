package com.googlecode.cryptogwttests;

import java.util.Arrays;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.googlecode.cryptogwt.tests.CipherTestVectors;
import com.googlecode.cryptogwt.tests.CryptoTestVector;

import static org.junit.Assert.*;


public class CipherTest {
    
    @BeforeClass
    public static void setUp() {
        Security.addProvider(JceAdaptorProvider.getInstance());
    }    
    
    @Test(expected=NoSuchAlgorithmException.class)
    public void throwsExceptionOnBogusCipherAlgorithm() throws NoSuchAlgorithmException,
        NoSuchPaddingException {
        Cipher.getInstance("Bogus Cipher Algorithm");
    }
    
    @Test(expected=NoSuchAlgorithmException.class)
    public void throwsExceptionOnBogusCipherMode() throws NoSuchAlgorithmException,
        NoSuchPaddingException {
        Cipher.getInstance("AES/Bogus Mode");
    }
    
    @Test(expected=NoSuchPaddingException.class)
    public void throwsExceptionOnBogusPadding() throws NoSuchAlgorithmException,
        NoSuchPaddingException {
        Cipher.getInstance("AES//Bogus Padding");
    }
    
    @Test
    public void haveTestVectors() {
        assertTrue(CipherTestVectors.INSTANCE.getAlgorithms().size() > 0);
    }
    
    
    @Test
    public void canLoadCiphers() throws NoSuchAlgorithmException, NoSuchPaddingException {
        for (String algorithm : CipherTestVectors.INSTANCE.getAlgorithms()) {
            assertNotNull(Cipher.getInstance(algorithm));
        }
    }
    
    @Test
    public void canEncrypt() throws GeneralSecurityException {
        for (String algorithm : CipherTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector :  CipherTestVectors.INSTANCE.get(algorithm)) {
                try {
                    testEncryptDecryptInSingleStep(algorithm, vector);
                    testEncryptDecryptUsingUpdateAndDoFinal(algorithm, vector);
                } catch (AssertionError e) {
                    AssertionError assertionFailed = new AssertionError("Test for \"" + algorithm +
                            "\" failed.\n" + vector);
                    assertionFailed.initCause(e);
                    throw assertionFailed;                   
                }
            }            
        }
    }

    private void testEncryptDecryptInSingleStep(String algorithm,
            CryptoTestVector vector) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        SecretKeySpec skeySpec = new SecretKeySpec(vector.key, cipherAlgorithm(algorithm));

        Cipher cipher = Cipher.getInstance(algorithm);

        if (vector.iv == null) {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(vector.iv));                           
        }

        byte[] encrypted =
            cipher.doFinal(vector.input);
        
        assertFalse(Arrays.equals(encrypted, vector.input));
        CipherTestVectors.assertOutputEquals(vector.expectedOutput, encrypted);

        if (vector.iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(vector.iv));                           
        }
        
        byte[] original = cipher.doFinal(encrypted);
        
        CipherTestVectors.assertOutputEquals(vector.input, original);
    }
    
    private void testEncryptDecryptUsingUpdateAndDoFinal(String algorithm,
            CryptoTestVector vector) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        SecretKeySpec skeySpec = new SecretKeySpec(vector.key, cipherAlgorithm(algorithm));

        Cipher cipher = Cipher.getInstance(algorithm);

        if (vector.iv == null) {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(vector.iv));                           
        }

        byte[] first = cipher.update(vector.input);
        byte[] second = cipher.doFinal();
        byte[] encrypted = concatenateArrays(first, second);
        
        assertFalse(Arrays.equals(encrypted, vector.input));
        assertArrayEquals(vector.expectedOutput, encrypted);

        if (vector.iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(vector.iv));                           
        }
        
        first = cipher.update(encrypted);
        second = cipher.doFinal();
        byte[] original = concatenateArrays(first, second);
        
        assertArrayEquals(vector.input, original);
    }

    private byte[] concatenateArrays(byte[] first, byte[] second) {
        byte[] encrypted = new byte[first.length + second.length];
        System.arraycopy(first, 0, encrypted, 0, first.length);
        System.arraycopy(second, 0, encrypted, first.length, second.length);
        return encrypted;
    }
    
    @Ignore // Use this to generate monte carlo tests
    public void generateRandomTestVectors() throws GeneralSecurityException, java.security.NoSuchAlgorithmException {
        final int NUMBER_OF_TESTS = 5;
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");
        int[] inputSizes = new int[] { 16, 32, 64 };
        for (String algorithm : new String[] { "AES//NoPadding", "AES/CBC/NoPadding"}) {
           
            for (int inputSize : inputSizes) {
                
                for (int i=0; i < NUMBER_OF_TESTS; i++) {
                    byte[] key = new byte[16];
                    random.nextBytes(key);

                    SecretKeySpec skeySpec = new SecretKeySpec(key, cipherAlgorithm(algorithm));

                    Cipher cipher = Cipher.getInstance(algorithm);

                    byte[] iv = null;
                    if (algorithm.contains("CBC")) {
                        iv = new byte[16];
                        random.nextBytes(iv);
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));

                    } else {            
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                    }
                                        
                    byte[] input = new byte[inputSize];
                    random.nextBytes(input);
                    
                    byte[] output = cipher.doFinal(input);
                    System.out.println("// Test#" + i + " for input of " + inputSize + " bytes");
                    System.out.println("add(\"" + algorithm + "\","); 
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(input) + "\"),");
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(key) + "\"),"); 
                    if (iv != null) System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(iv) + "\"),");
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(output) + "\"));\n");
                }

            }
        }
    }
    
    @Ignore // Use this to generate monte carlo tests
    public void generateRandomTestVectorsForPkcs5Padding() throws GeneralSecurityException, java.security.NoSuchAlgorithmException {
        final int NUMBER_OF_TESTS = 1;
        java.security.SecureRandom random = new java.security.SecureRandom();
        int[] inputSizes = new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 32, 33 };
        for (String algorithm : new String[] { "AES//PKCS5Padding", "AES/CBC/PKCS5Padding"}) {
           
            for (int inputSize : inputSizes) {
                
                for (int i=0; i < NUMBER_OF_TESTS; i++) {
                    byte[] key = new byte[16];
                    random.nextBytes(key);

                    SecretKeySpec skeySpec = new SecretKeySpec(key, cipherAlgorithm(algorithm));

                    Cipher cipher = Cipher.getInstance(algorithm);

                    byte[] iv = null;
                    if (algorithm.contains("CBC")) {
                        iv = new byte[16];
                        random.nextBytes(iv);
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));

                    } else {            
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                    }
                                        
                    byte[] input = new byte[inputSize];
                    random.nextBytes(input);
                    
                    byte[] output = cipher.doFinal(input);
                    System.out.println("// Test#" + i + " for input of " + inputSize + " bytes");
                    System.out.println("add(\"" + algorithm + "\","); 
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(input) + "\"),");
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(key) + "\"),"); 
                    if (iv != null) System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(iv) + "\"),");
                    System.out.println("    hexToBytes(\"" + CryptoTestVector.toHexString(output) + "\"));\n");
                }

            }
        }
    }

    private String cipherAlgorithm(String algorithm) {
        return algorithm.split("/")[0];
    }
}
