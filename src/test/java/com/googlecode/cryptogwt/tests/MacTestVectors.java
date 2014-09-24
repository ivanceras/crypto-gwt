package com.googlecode.cryptogwt.tests;

import static com.googlecode.cryptogwt.util.ByteArrayUtils.*;

public class MacTestVectors extends CryptoTestVectors {
    public static MacTestVectors INSTANCE = new MacTestVectors();
    private MacTestVectors() {
        // RFC4231: Test Case 1
        add("HmacSHA256",
                asciiToBytes("Hi There"),
                hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                hexToBytes("b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7"));
        
        
        // RFC4231: Test Case 2 Test with a key shorter than the length of the HMAC output.
        add("HmacSHA256",
                hexToBytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
                hexToBytes("4a656665"),
                hexToBytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        
        // RFC4231: Test Case 3 Test with a combined length of key and data that is larger than
        // 64 bytes
        add("HmacSHA256", 
            hexToBytes("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" +
                       "dddddddddddddddddddddddddddddddddddd"),
            hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            hexToBytes("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
        
        // RFC4231: Test Case 4 Test with a combined length of key and data that is larger than 
        // 64 bytes
        add("HmacSHA256", 
                hexToBytes("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" + 
                		   "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
                hexToBytes("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                hexToBytes("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
        
        // RFC4231: Test Case 6 Test with a key larger than 128 bytes
        add("HmacSHA256", 
                hexToBytes("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a" +
                           "65204b6579202d2048617368204b6579204669727374"),
                hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaa"),
                hexToBytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
        
        // RFC4231: Test Case 7 Test with a key and data that is larger than 128 bytes
        add("HmacSHA256", 
                hexToBytes("5468697320697320612074657374207573696e672061206c6172676572207468" +
                           "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" +
                           "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565" +
                           "647320746f20626520686173686564206265666f7265206265696e6720757365" +
                           "642062792074686520484d414320616c676f726974686d2e"),
                hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaa"),
                hexToBytes("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));

        // RFC2202: Test case 1
        add("HmacSHA1",
                asciiToBytes("Hi There"),
                hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                hexToBytes("b617318655057264e28bc0b6fb378c8ef146be00"));
        
        // RFC2202: Test case 2
        add("HmacSHA1",
                asciiToBytes("what do ya want for nothing?"),
                asciiToBytes("Jefe"),
                hexToBytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
        
        // RFC2202: Test case 3
        add("HmacSHA1",
                repeat((byte)0xdd, 50),
                hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                hexToBytes("125d7342b9ac11cd91a39af48aa17b4f63f175d3"));
        
        // RFC2202: Test case 4
        add("HmacSHA1",
                repeat((byte)0xcd, 50),
                hexToBytes("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                hexToBytes("4c9007f4026250c6bc8414f9bf50c86c2d7235da"));
        
        // RFC2202: Test case 6
        add("HmacSHA1",
                asciiToBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
                repeat((byte)0xaa, 80),
                hexToBytes("aa4ae5e15272d00e95705637ce8a3b55ed402112")
                );
        
        // RFC2202: Test case 7
        add("HmacSHA1",
                asciiToBytes("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
                repeat((byte)0xaa, 80),
                hexToBytes("e8e99d0f45237d786d6bbaa7965c7808bbff1a91")
                );
        
        
        // Properties
        setProperty("HmacSHA256", "macLength", 32);
        
        setProperty("HmacSHA1", "macLength", 20);
    }

    
    
}
