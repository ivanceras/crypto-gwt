package com.googlecode.cryptogwt.tests;


public class MessageDigestTestVectors extends CryptoTestVectors  {
    
    public static CryptoTestVectors INSTANCE = new MessageDigestTestVectors();
    
    private MessageDigestTestVectors() {
        add("SHA-256", 
            new byte[] {}, 
            hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")); 
        add("SHA-256",
            asciiToBytes("abc"),
            hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        add("SHA-256",
            asciiToBytes("message digest"),
            hexToBytes("f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"));
        add("SHA-256",
            asciiToBytes("secure hash algorithm"),
            hexToBytes("f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d"));
        add("SHA-256",
            asciiToBytes("SHA256 is considered to be safe"),
            hexToBytes("6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630"));
        add("SHA-256",
            asciiToBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hexToBytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
        add("SHA-256",
            asciiToBytes("For this sample, this 63-byte string will be used as input data"),
            hexToBytes("f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342"));
        add("SHA-256",
            asciiToBytes("This is exactly 64 bytes long, not counting the terminating byte"),
            hexToBytes("ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8"));
        add("SHA-256",
                hexToBytes("739b7d01f0d4ca3c1acaf783ec647704da464023f4fcd7ed8a75ff4c9317edb7" +
                           "3636363636363636363636363636363636363636363636363636363636363636" +
                		   "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a" + 
                		   "65204b6579202d2048617368204b6579204669727374"),
                hexToBytes("a73038bbcc5d6f033721558ca481f37472ca01c3b4072f325c1072a192bfe2c0"));
        
        // Zero length
        add("SHA1",
                new byte[] {},
                hexToBytes("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        
        // Nist One Block Example
        add("SHA1",
                asciiToBytes("abc"),
                hexToBytes("a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"));
        
        // Nist Two Block Example
        add("SHA1",
                asciiToBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                hexToBytes("84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"));
        

        
        // Monte-carlo tests
     // Test#0 for input of 1 bytes
        add("SHA1",
            hexToBytes("44"),
            hexToBytes("50c9e8d5fc98727b4bbc93cf5d64a68db647f04f"));

        // Test#0 for input of 2 bytes
        add("SHA1",
            hexToBytes("1ccb"),
            hexToBytes("85f1d60f3f7f8a9f208310c42b84588b90cca7e5"));

        // Test#0 for input of 3 bytes
        add("SHA1",
            hexToBytes("df3922"),
            hexToBytes("a40305d4f0e2bccdc906acba33c640b4279a4f1d"));

        // Test#0 for input of 4 bytes
        add("SHA1",
            hexToBytes("e2710a5d"),
            hexToBytes("5344bb82dc3b70ec24c809009b1c5a7c70cdd513"));

        // Test#0 for input of 5 bytes
        add("SHA1",
            hexToBytes("85f00ac863"),
            hexToBytes("c944ec9ea4a08863b3c6de7185929a96d44b1d7a"));

        // Test#0 for input of 6 bytes
        add("SHA1",
            hexToBytes("749f9070aa84"),
            hexToBytes("9d839ee192a82fdf2445bf8caf4504ef98048af3"));

        // Test#0 for input of 7 bytes
        add("SHA1",
            hexToBytes("363fc9d89c8c4d"),
            hexToBytes("4c97bdfe59f95889187184ece4e513957a8ecf36"));

        // Test#0 for input of 8 bytes
        add("SHA1",
            hexToBytes("b7699f90755a474f"),
            hexToBytes("32880b53d4dbee8b9670b147f23016664f5aee6b"));

        // Test#0 for input of 9 bytes
        add("SHA1",
            hexToBytes("ddb0dddf567955b218"),
            hexToBytes("b698834918fa8fa9cf24c17cc8991eb0b9c7d4f3"));

        // Test#0 for input of 16 bytes
        add("SHA1",
            hexToBytes("63c591e18c1b8c3fe1f047335a6ca2e6"),
            hexToBytes("5d434d37ae8470ec993c6b66570a75c03ecddb5e"));

        // Test#0 for input of 17 bytes
        add("SHA1",
            hexToBytes("0d0e938af42d725b680ddb5fa0b3233dae"),
            hexToBytes("043f4ef4b0d39ba2f5031a9ca988dbe5d3d939fa"));

        // Test#0 for input of 32 bytes
        add("SHA1",
            hexToBytes("3630e795cd6db492a72d10e5ce2fadffb54b6ebd429766db3958ec55b0d9486b"),
            hexToBytes("feb349087d508a0fb138176f6c19c2378a9d23e7"));

        // Test#0 for input of 31 bytes
        add("SHA1",
            hexToBytes("c585319c2e5308e92886e7aa88f3b6441514e380b3d369ea14a5814f9819dd"),
            hexToBytes("a4bb5c70fbc3f1adf7260b287148d0b484d4d044"));

        // Test#0 for input of 64 bytes
        add("SHA1",
            hexToBytes("91fb32833c9efdb5bc1682c18f2d510f94e9e37fdc5d9fdcc3985ac576c161dc6ba4ebf89cb14ff4c15c0d1d55b74ab2d7b4e2f43c8073594a243b1f49eff09e"),
            hexToBytes("15c5f78e71ef06bb59be812bf367c2bf4b2f27a2"));

        // Test#0 for input of 65 bytes
        add("SHA1",
            hexToBytes("b56058ed321a5675c6b4fb6a948a0999ee27b8562a392ceadb9956b2adf7c48e7f0946d308eb97e6acef5cb8670f9aae8fd203376f6c05001afe72f87fb153895e"),
            hexToBytes("d99496ace21cf5bff30ab22ab83df3adea752e0b"));

        // Test#0 for input of 1 bytes
        add("SHA-256",
            hexToBytes("e1"),
            hexToBytes("f031efa58744e97a34555ca98621d4e8a52ceb5f20b891d5c44ccae0daaaa644"));

        // Test#0 for input of 2 bytes
        add("SHA-256",
            hexToBytes("7497"),
            hexToBytes("61240dc7d2635dbe7fd652903fa4a23ee8b734aba0747b3d1e6dabaf04f16c33"));

        // Test#0 for input of 3 bytes
        add("SHA-256",
            hexToBytes("feab17"),
            hexToBytes("5df934cb47705142e7e73037154a1918d4eae80e34192b881f98ccd245738955"));

        // Test#0 for input of 4 bytes
        add("SHA-256",
            hexToBytes("73843716"),
            hexToBytes("fe669e49487c6d4ffeaf939d310972ce2e3b3cb55a8407f804b5883e8fc52a19"));

        // Test#0 for input of 5 bytes
        add("SHA-256",
            hexToBytes("6927de8eff"),
            hexToBytes("79f4434974e20a76d56878960c9f53adcc42913a4a3a0796f22202437b4ce1ed"));

        // Test#0 for input of 6 bytes
        add("SHA-256",
            hexToBytes("d3bde642bc84"),
            hexToBytes("f4d4570fb6a2e019ba406d633cc7c9b109fd04048d51dab260710ee054423c0b"));

        // Test#0 for input of 7 bytes
        add("SHA-256",
            hexToBytes("772d2a397d9dd6"),
            hexToBytes("e0e2f0d097f976abda5be0805fcfa46a4476a45d0a00c1ae8ed9a3e9cfc0a5f6"));

        // Test#0 for input of 8 bytes
        add("SHA-256",
            hexToBytes("14825976b67631ba"),
            hexToBytes("0e465c21002022924a637907d191859b0d5ce866443e3902d057be7483cd74f9"));

        // Test#0 for input of 9 bytes
        add("SHA-256",
            hexToBytes("df72a6003ec271dc52"),
            hexToBytes("3e64ae6c198d6b1f5a4fd3a67a6d422b8f04fb3abe159186a175869dc2f51c24"));

        // Test#0 for input of 16 bytes
        add("SHA-256",
            hexToBytes("abd53f8bb1fe1f25a3c1517c20463a94"),
            hexToBytes("a5b55639504a921496ef701cbbc8f45f6996a646bcc338f4944d07b936cf5736"));

        // Test#0 for input of 17 bytes
        add("SHA-256",
            hexToBytes("7e3d2773684559e1c3b29ec4ba06f90149"),
            hexToBytes("925e521d89f441c24dbed58e23f4150f78b39f75f5284594504608190a2d290c"));

        // Test#0 for input of 32 bytes
        add("SHA-256",
            hexToBytes("67010eaf9a5c351668592620947b5f851eab4ac21a4017114c6944e810bebb81"),
            hexToBytes("9760c5d5526fadbcaef1fb250bc682f11e9624de1e0993337a141a994aba4ccd"));

        // Test#0 for input of 31 bytes
        add("SHA-256",
            hexToBytes("f4fc86621253a89c0dc00591a15f40ff445bc4bd2c78dd8de4b5655f0983d8"),
            hexToBytes("e2db33292c4575971db22b1e9e8217408fb476cea9badf7530229a64a36bd0d0"));

        // Test#0 for input of 64 bytes
        add("SHA-256",
            hexToBytes("4eac105c807707b9c0c1789cf580d7ba2c2e9825e54a0919a6ef903d307e1b03fb16362b4e46aad436a8fa7abd48323d4b28d3dbf0c082c09dd4c9e7269c0719"),
            hexToBytes("18e0c0a693740e2ab0297e5e7d74488c03fde2d927e8acc6f62017f0a6de63e5"));

        // Test#0 for input of 65 bytes
        add("SHA-256",
            hexToBytes("098fecfa70301313366593168556cef40d96af570bdb64938414bb2ef6aa7be66183969f1ccbc9ef4b136f2dcc354afbd169ba2b5c724a3ceedb948ea77e256de4"),
            hexToBytes("0c15ddb01e85bd6ad6dcf9bf361db04356ac4d64045c2eacb2a83bcca2a4c5c1"));



        setProperty("SHA-256", "digestLength", 32);
        setProperty("SHA1", "digestLength", 20);
    }
    
}
