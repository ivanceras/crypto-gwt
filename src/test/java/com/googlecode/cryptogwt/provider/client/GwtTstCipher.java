package com.googlecode.cryptogwt.provider.client;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gwt.core.client.GWT;
import com.googlecode.cryptogwt.provider.CryptoGwtProvider;
import com.googlecode.cryptogwt.tests.CipherTestVectors;
import com.googlecode.cryptogwt.tests.CryptoTestVector;

public class GwtTstCipher extends CryptoGwtProviderGWTTestCase {

    // @Test(expected=NoSuchAlgorithmException.class)
    // public void throwsExceptionOnBogusCipherAlgorithm() throws
    // NoSuchAlgorithmException,
    // NoSuchPaddingException {
    // Cipher.getInstance("Bogus Cipher Algorithm");
    // }
    //        
    // @Test(expected=NoSuchAlgorithmException.class)
    // public void throwsExceptionOnBogusCipherMode() throws
    // NoSuchAlgorithmException,
    // NoSuchPaddingException {
    // Cipher.getInstance("AES/Bogus Mode");
    // }
    //        
    // @Test(expected=NoSuchPaddingException.class)
    // public void throwsExceptionOnBogusPadding() throws
    // NoSuchAlgorithmException,
    // NoSuchPaddingException {
    // Cipher.getInstance("AES//Bogus Padding");
    // }

    public void testHaveTestVectors() {
        assertTrue(CipherTestVectors.INSTANCE.getAlgorithms().size() > 0);
    }

    public void testCanLoadCiphers() throws NoSuchAlgorithmException,
            NoSuchPaddingException {
        assertTrue(GWT.isClient());
        init();
        for (String algorithm : CipherTestVectors.INSTANCE.getAlgorithms()) {
            assertNotNull(Cipher.getInstance(algorithm));
        }
    }

    private void init() {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
    }

    public void testCanEncrypt() throws GeneralSecurityException {
        init();
        for (String algorithm : CipherTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : CipherTestVectors.INSTANCE
                    .get(algorithm)) {
                try {
                    testEncryptDecryptInSingleStep(algorithm, vector);
                    testEncryptDecryptUsingUpdateAndDoFinal(algorithm, vector);
                } catch (AssertionError e) {
                    AssertionError assertionFailed = new AssertionError(
                            "Test for \"" + algorithm + "\" failed.\n" + vector);
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
        init();
        
        SecretKeySpec skeySpec = new SecretKeySpec(vector.key,
                cipherAlgorithm(algorithm));

        Cipher cipher = Cipher.getInstance(algorithm);

        if (vector.iv == null) {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(
                    vector.iv));
        }

        byte[] encrypted = cipher.doFinal(vector.input);

        assertFalse(Arrays.equals(encrypted, vector.input));
        CipherTestVectors.assertOutputEquals(vector.expectedOutput, encrypted);

        if (vector.iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(
                    vector.iv));
        }

        byte[] original = cipher.doFinal(encrypted);

        CipherTestVectors.assertOutputEquals(vector.input, original);
    }

    private void testEncryptDecryptUsingUpdateAndDoFinal(String algorithm,
            CryptoTestVector vector) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        init();
        
        SecretKeySpec skeySpec = new SecretKeySpec(vector.key,
                cipherAlgorithm(algorithm));

        Cipher cipher = Cipher.getInstance(algorithm);

        if (vector.iv == null) {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(
                    vector.iv));
        }

        byte[] first = cipher.update(vector.input);
        byte[] second = cipher.doFinal();
        byte[] encrypted = concatenateArrays(first, second);

        assertFalse(Arrays.equals(encrypted, vector.input));
        CipherTestVectors.assertOutputEquals(vector.expectedOutput, encrypted);

        if (vector.iv == null) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(
                    vector.iv));
        }

        first = cipher.update(encrypted);
        second = cipher.doFinal();
        byte[] original = concatenateArrays(first, second);

        CipherTestVectors.assertOutputEquals(vector.input, original);
    }

    private byte[] concatenateArrays(byte[] first, byte[] second) {
        byte[] encrypted = new byte[first.length + second.length];
        System.arraycopy(first, 0, encrypted, 0, first.length);
        System.arraycopy(second, 0, encrypted, first.length, second.length);
        return encrypted;
    }
    

    private String cipherAlgorithm(String algorithm) {
        return algorithm.split("/")[0];
    }

}
