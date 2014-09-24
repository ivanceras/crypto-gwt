/**
 * 
 */
package com.googlecode.cryptogwt.tests;

public class CryptoTestVector {
    
    public final byte[] key;
    
    public final byte[] iv;
    
    public final byte[] input;
    
    public final byte[] expectedOutput;    
    
    public CryptoTestVector(byte[] input, byte[] expectedOutput) {
        this(input, null, null, expectedOutput);
    }
    
    public CryptoTestVector(byte[] input, byte[] key, byte[] expectedOutput) {
        this(input, key, null, expectedOutput);        
    }
    
    public CryptoTestVector(byte[] input, byte[] key, byte[] iv, byte[] expectedOutput) {
        this.key = key;
        this.iv = iv;
        this.input = input;
        this.expectedOutput = expectedOutput;
    }

    @Override
    public String toString() {
        return "TestVector ["
                + "expectedOutput=" + toHexString(expectedOutput)
                + (input != null ? ", input=" + toHexString(input) : "")
                + (iv != null ? ", iv=" + toHexString(iv) : "")
                + (key != null ? ", key=" + toHexString(key) : "") + "]";
    }
    
    public static String toHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(Integer.toHexString((b >> 4) & 0xf));
            builder.append(Integer.toHexString(b & 0xf));
        }        
        return builder.toString();
    }
    
    public static String toHexString(byte[] bytes, int offset, int len) {
        StringBuilder builder = new StringBuilder();
        int i =0;
        for (byte b : bytes) {
            if (i == offset) builder.append("[");
            builder.append(Integer.toHexString((b >> 4) & 0xf));
            builder.append(Integer.toHexString(b & 0xf));
            if (++i == (offset + len)) builder.append("]");
        }        
        return builder.toString();
    }
    
    
    
}