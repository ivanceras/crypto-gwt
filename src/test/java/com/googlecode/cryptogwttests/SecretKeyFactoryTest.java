package com.googlecode.cryptogwttests;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import com.googlecode.cryptogwt.tests.CryptoTestVector;
import com.googlecode.cryptogwt.tests.PbeSecretKeyFactoryTestVectors;

import static com.googlecode.cryptogwt.tests.CryptoTestVectors.assertOutputEquals;
import static com.googlecode.cryptogwt.util.ByteArrayUtils.*;

public class SecretKeyFactoryTest {
    
    @BeforeClass
    public static void setUp() {
        Security.addProvider(JceAdaptorProvider.getInstance());
    }
    
    
    @Test
    public void testPasswordBasedkeyDerivation() throws GeneralSecurityException {
        // Note: vector.key = password, vector.input = salt, vector.iv = iterations.
        for (String algorithm : PbeSecretKeyFactoryTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : PbeSecretKeyFactoryTestVectors.INSTANCE.get(algorithm)) {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
                SecretKey result = factory.generateSecret(new PBEKeySpec(
                        toAsciiString(vector.key).toCharArray(),
                        vector.input,
                        toInteger(vector.iv),
                        vector.expectedOutput.length * 8));                
                assertOutputEquals(vector.expectedOutput, result.getEncoded());
                
            }
        }
    }
    
    @Ignore
    public void generateRandomTestVectorsForPasswordBasedKeyDerivation() throws GeneralSecurityException, java.security.NoSuchAlgorithmException {
        java.security.SecureRandom random = new java.security.SecureRandom();
        int[] outputSizes = new int[] { 16 * 8, 32 * 8 };
        int[] iterationCounts = new int[] { 1000 };
        String password = "secret";
        for (String algorithm : new String[] { "PBKDF2WithHmacSHA1"}) {
           
            for (int outputSize : outputSizes) {
                
                for (int iterationCount : iterationCounts ) {
                    byte[] salt = new byte[16];
                    random.nextBytes(salt);                                        
                    SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
                    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, outputSize);
                    SecretKey outputKey = factory.generateSecret(spec);
                    
                    System.out.println("// Test with iteration count " + iterationCount + " for keyLen of " + outputSize/8 + " bytes");
                    System.out.println("add(\"" + algorithm + "\",");                     
                    System.out.println("    hexToBytes(\"" + toHexString(salt) + "\"),");
                    System.out.println("    asciiToBytes(\"" + password + "\"),");
                    System.out.println("    toBytes(" + iterationCount + "),");
                    System.out.println("    hexToBytes(\"" + toHexString(outputKey.getEncoded()) + "\"));\n");
                }

            }
        }
    }


}
