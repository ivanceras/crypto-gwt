package com.googlecode.cryptogwt.tests;

import static com.googlecode.cryptogwt.util.ByteArrayUtils.*;

public class PbeSecretKeyFactoryTestVectors extends CryptoTestVectors {
    
    public static CryptoTestVectors INSTANCE = new PbeSecretKeyFactoryTestVectors();
    
    public PbeSecretKeyFactoryTestVectors() {
     // Test for keyLen of 16 bytes
        add("PBKDF2WithHmacSHA1",
            hexToBytes("d3ea11eb327057ee416c57162f430d5b"),
            asciiToBytes("secret"),
            toBytes(1000),
            hexToBytes("cf8fb0f31670bde11a1dc6d9902ce909"));

        // Test for keyLen of 32 bytes
        add("PBKDF2WithHmacSHA1",            
            hexToBytes("4c952042300ca8d729702819bf54b79d"),
            asciiToBytes("secret"),
            toBytes(1000),
            hexToBytes("963227b593ae084c9db144c566b5ec09a35444d133ba761caef6618d7bb0e2da"));
        
        add("PBKDF2WithHmacSHA1",            
                asciiToBytes("ATHENA.MIT.EDUraeburn"),
                asciiToBytes("password"),
                toBytes(1),
                hexToBytes("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15"));
        
        add("PBKDF2WithHmacSHA1",            
                asciiToBytes("ATHENA.MIT.EDUraeburn"),
                asciiToBytes("password"),
                toBytes(1),
                hexToBytes("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37"));
        
        add("PBKDF2WithHmacSHA1",            
                asciiToBytes("ATHENA.MIT.EDUraeburn"),
                asciiToBytes("password"),
                toBytes(2),
                hexToBytes("01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d"));
        
        add("PBKDF2WithHmacSHA1",            
                asciiToBytes("ATHENA.MIT.EDUraeburn"),
                asciiToBytes("password"),
                toBytes(2),
                hexToBytes("01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86"));
        
        add("PBKDF2WithHmacSHA1",            
                asciiToBytes("ATHENA.MIT.EDUraeburn"),
                asciiToBytes("password"),
                toBytes(1200),
                hexToBytes("5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13"));
    }

}
