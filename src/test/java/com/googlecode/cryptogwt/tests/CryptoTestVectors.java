package com.googlecode.cryptogwt.tests;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.googlecode.cryptogwt.tests.CryptoTestVector.toHexString;

public class CryptoTestVectors {

    public Map<String, List<CryptoTestVector>> testVectors = new LinkedHashMap<String, List<CryptoTestVector>>();
    public Map<String, Object> properties = new LinkedHashMap<String, Object>();

    public List<CryptoTestVector> get(String algorithm) {
        return testVectors.get(algorithm);
    }

    public Set<String> getAlgorithms() { return testVectors.keySet(); }

    public static byte[] hexToBytes(String hex) {        
        hex = removeSpaces(hex); // Remove spaces
        assert hex.length() % 2 == 0 : "must be even number of characters: \"" + hex + "\"";
        int resultLen = hex.length()/2;
        byte[] result = new byte[resultLen];
        int j=0;
        for (int i=0; i < resultLen; i++) {            
            result[i] = (byte) (Byte.parseByte(hex.substring(j, ++j), 16) << 4 |
                    Byte.parseByte(hex.substring(j, ++j), 16));
        }
        return result;
    }

    private static String removeSpaces(String string) {
        string = string.replaceAll("\\s+", "");
        return string;
    }
    
    public static void assertOutputEquals(String expectedHexString, byte[] actualBytes) {
        assertOutputEquals(expectedHexString, toHexString(actualBytes));
    }
    
    public static void assertOutputEquals(byte[] expectedBytes, byte[] actualBytes) {
        assertOutputEquals(toHexString(expectedBytes), toHexString(actualBytes));
    }
    
    public static void assertOutputEquals(CryptoTestVector vector, byte[] actualBytes) {
        try {
            assertOutputEquals(vector.expectedOutput, actualBytes);
        } catch (AssertionError error) {
            AssertionError wrapped = new AssertionError("Test vector failed.\n" + vector);
            wrapped.initCause(error);
            throw wrapped;
        }
    }
    
    public static void assertOutputEquals(String expectedHexString, String actualHexString) {
        expectedHexString = removeSpaces(expectedHexString);
        actualHexString = removeSpaces(actualHexString);
        if (!expectedHexString.equals(actualHexString)) {
            throw new AssertionError("bytes: " + actualHexString + " does not match expected value " + 
                    expectedHexString);
        }       
    }

    public static byte[] asciiToBytes(String ascii) {
        char[] chars = ascii.toCharArray();
        int resultLen = chars.length;
        byte[] result = new byte[resultLen];
        for (int i=0; i < resultLen; i++) {
            result[i] = (byte) (chars[i] & 0xff);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public <T> T getProperty(String algorithm, String propertyName, @SuppressWarnings("unused") Class<T> type) {
        return (T) properties.get(algorithm + "::" + propertyName);
    }

    public <T> void setProperty(String algorithm, String propertyName, T value) {
        properties.put(algorithm + "::" + propertyName, value);
    }
    
    public void add(String algorithm, byte[] input, byte[] key,
            byte[] iv, byte[] expected) {
        add(algorithm, new CryptoTestVector(input, key, iv, expected));
    }

    public void add(String algorithm, byte[] input, byte[] key,
            byte[] expected) {
        add(algorithm, new CryptoTestVector(input, key, null, expected));
    }

    public void add(String algorithm, byte[] input, byte[] expected) {
        add(algorithm, new CryptoTestVector(input, expected));      
    }

    public void add(String algorithm, final CryptoTestVector vector) {
        List<CryptoTestVector> vectors = get(algorithm);
        if (vectors == null) {
            vectors = new ArrayList<CryptoTestVector>();
            testVectors.put(algorithm, vectors);
        }        
        vectors.add(vector);
    }
    
    public CryptoTestVectors() {
        super();
    }

}