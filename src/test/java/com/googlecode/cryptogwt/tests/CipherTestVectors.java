package com.googlecode.cryptogwt.tests;

public class CipherTestVectors extends CryptoTestVectors {
    
    public static CipherTestVectors INSTANCE = new CipherTestVectors();
    
    private CipherTestVectors() {
        setProperty("AES", "keySize", 128);
        
        // From FIPS 197
        add("AES//NoPadding", 
                hexToBytes("00112233445566778899aabbccddeeff"),
                hexToBytes("000102030405060708090a0b0c0d0e0f"),
                hexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a"));
        
        // From AES Known Answer Test (KAT)
        // ECB Tests
        add("AES//NoPadding",
                hexToBytes("f34481ec3cc627bacd5dc3fb08f273e6"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("0336763e966d92595a567cc9ce537f5e"));
                        
        add("AES//NoPadding",
                hexToBytes("9798c4640bad75c7c3227db910174e72"),
                hexToBytes("00000000000000000000000000000000"),     
                hexToBytes("a9a1631bf4996954ebc093957b234589"));

        add("AES//NoPadding",
                hexToBytes("96ab5c2ff612d9dfaae8c31f30c42168"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("ff4f8391a6a40ca5b25d23bedd44a597"));
        
        add("AES//NoPadding",
                hexToBytes("6a118a874519e64e9963798a503f1d35"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("dc43be40be0e53712f7e2bf5ca707209"));
        
        add("AES//NoPadding",
                hexToBytes("cb9fceec81286ca3e989bd979b0cb284"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("92beedab1895a94faa69b632e5cc47ce"));
        
        add("AES//NoPadding",
                hexToBytes("b26aeb1874e47ca8358ff22378f09144"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("459264f4798f6a78bacb89c15ed3d601"));
        
        
        add("AES//NoPadding",
                hexToBytes("58c8e00b2631686d54eab84b91f0aca1"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("08a4e2efec8a8e3312ca7460b9040bbf"));
        
        // From FIPS 197
        add("AES//NoPadding", 
                hexToBytes("00112233445566778899aabbccddeeff"),
                hexToBytes("000102030405060708090a0b0c0d0e0f"),
                hexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a"));
        
        // From AES Known Answer Test (KAT)
        // ECB Tests
        add("AES/ECB/NoPadding",
                hexToBytes("f34481ec3cc627bacd5dc3fb08f273e6"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("0336763e966d92595a567cc9ce537f5e"));
                        
        add("AES/ECB/NoPadding",
                hexToBytes("9798c4640bad75c7c3227db910174e72"),
                hexToBytes("00000000000000000000000000000000"),     
                hexToBytes("a9a1631bf4996954ebc093957b234589"));

        add("AES/ECB/NoPadding",
                hexToBytes("96ab5c2ff612d9dfaae8c31f30c42168"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("ff4f8391a6a40ca5b25d23bedd44a597"));
        
        add("AES/ECB/NoPadding",
                hexToBytes("6a118a874519e64e9963798a503f1d35"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("dc43be40be0e53712f7e2bf5ca707209"));
        
        add("AES/ECB/NoPadding",
                hexToBytes("cb9fceec81286ca3e989bd979b0cb284"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("92beedab1895a94faa69b632e5cc47ce"));
        
        add("AES/ECB/NoPadding",
                hexToBytes("b26aeb1874e47ca8358ff22378f09144"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("459264f4798f6a78bacb89c15ed3d601"));
                
        add("AES/ECB/NoPadding",
                hexToBytes("58c8e00b2631686d54eab84b91f0aca1"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("08a4e2efec8a8e3312ca7460b9040bbf"));
        
        // From AES Known Answer Test (KAT)
        // CBC Tests
        add("AES/CBC/NoPadding",
                hexToBytes("80000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("3ad78e726c1ec02b7ebfe92b23d9ec34"));
        
        add("AES/CBC/NoPadding",
                hexToBytes("c0000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("aae5939c8efdf2f04e60b9fe7117b2c2"));
        
        add("AES/CBC/NoPadding",
                hexToBytes("e0000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("f031d4d74f5dcbf39daaf8ca3af6e527"));

        add("AES/CBC/NoPadding",
                hexToBytes("f0000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("96d9fd5cc4f07441727df0f33e401a36"));

        add("AES/CBC/NoPadding",
                hexToBytes("f8000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("30ccdb044646d7e1f3ccea3dca08b8c0"));
        
        add("AES/CBC/NoPadding",
                hexToBytes("fc000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("00000000000000000000000000000000"),
                hexToBytes("16ae4ce5042a67ee8e177b7c587ecc82"));
        
        // Monte Carlo tests generated from JCE
     // Test#0 for input of 16 bytes
        add("AES//NoPadding",
            hexToBytes("8aae756f1b1f096c46b147450efbdb37"),
            hexToBytes("e5d5318881504f16d200295bac31e282"),
            hexToBytes("0f5bb2d01f7c34f0ed03772fe748b5a6"));

        // Test#1 for input of 16 bytes
        add("AES//NoPadding",
            hexToBytes("6b8dd1bfc5b634a0b14d0a97f4573eb3"),
            hexToBytes("ab52e9a461a9adb370ea6cf707a89435"),
            hexToBytes("3b401d5141928b34116f45f56e099f16"));

        // Test#2 for input of 16 bytes
        add("AES//NoPadding",
            hexToBytes("2f486cab12b3b8b481396dce6dbdaf91"),
            hexToBytes("e8d29add7586993e93f9a44f5b913b1b"),
            hexToBytes("561c0b0dce9bcdb137d08f90d4392aa9"));

        // Test#3 for input of 16 bytes
        add("AES//NoPadding",
            hexToBytes("4685ffc9409223fb200beedcb3da72e9"),
            hexToBytes("f193e01266af373c0bce6d04e4ac8c36"),
            hexToBytes("1325292bd29e32514c2a4861732c93e9"));

        // Test#4 for input of 16 bytes
        add("AES//NoPadding",
            hexToBytes("6bdf8fad313d1ea8c8f007bce30943b1"),
            hexToBytes("4f89d2daf499bf427b462eef4ec9dee5"),
            hexToBytes("33a0bb6d0861f34dfc71f5c664f8b038"));

        // Test#0 for input of 32 bytes
        add("AES//NoPadding",
            hexToBytes("8bfa182be3d3391eed5bf0a3c96a44a4b87f5bdf2033034a856d1f7d7aaf762d"),
            hexToBytes("845f2c95c32ddcb96b8912a1dd47dd66"),
            hexToBytes("723570cb79783276ab3b659677bd6a972fbd8a09adbcd2fd8f57107c80805521"));

        // Test#1 for input of 32 bytes
        add("AES//NoPadding",
            hexToBytes("5aafe857abeb12815e01b1dc5aec94fdb5b6c849dcbba9a18b54c7c7829ed020"),
            hexToBytes("f59a7ddd60197ad30f186e2bf1f000be"),
            hexToBytes("9f716ca20000b3920374c63124ce84a86fa0a4aa225028185fc20d2a15f9aed7"));

        // Test#2 for input of 32 bytes
        add("AES//NoPadding",
            hexToBytes("ec9e645eaa89804c023798ac62f9720c84bb52d798b74dfe294389ec81abc4ec"),
            hexToBytes("5a45a49c90d11adcc5a089d7b05af53e"),
            hexToBytes("47433f819e68aa87519843431c2d87be24f3ab6a914403a5b7dfc4d8408c4f90"));

        // Test#3 for input of 32 bytes
        add("AES//NoPadding",
            hexToBytes("5f758cabbc4ecdbee5f107147481e5fbbdc83087010670a31d3184babdc630e0"),
            hexToBytes("6ecb2a6dcf44b7aa34131d4a7b0fee93"),
            hexToBytes("01a56f4345f86532478d2981cbd9781e2816ab323f14896cc33b1c42188c63de"));

        // Test#4 for input of 32 bytes
        add("AES//NoPadding",
            hexToBytes("c009ac179fff9be5129d56083f450db5d48782d777232c353b18373ecdf8e7a6"),
            hexToBytes("c3cb9d82af3e3e2afd9fdbec5a6da837"),
            hexToBytes("cc869f85f0f291cf50694d0b5d1689b899d16d26449446b5687dd57c53414be7"));

        // Test#0 for input of 64 bytes
        add("AES//NoPadding",
            hexToBytes("ddb724866a5976fa31793aae0c2ff8dc49aa097310e450c80c58218ec0898cd173f54ce08c0a03c1db6e438099e319b4bd1706ddbaea068352c52eb43dbca6ac"),
            hexToBytes("6a283c6f80d85350c86496cbabb3d53d"),
            hexToBytes("8c7149ba08dc27083e575fede8ca7e5edc71d653ef8da42c5c54513356076bd55cb215a34eb3ae26f025b6ca0526343237566b360f32a9fb05b1e77dff9c8265"));

        // Test#1 for input of 64 bytes
        add("AES//NoPadding",
            hexToBytes("a399cbdd1272231c5bb21a73a180d4d1a46328e7bc65b19874f1f0d82609f70685d73b8e3e23ba2d6cf060ac9d7a953044dfc2a699fe89e678306e08ab4aa1d3"),
            hexToBytes("091cdb36dc02532692bf27368354b559"),
            hexToBytes("054cf5e28b581fdbf1d18b84fae7f5945fa51648ae199ba6970e6398912d2f12ec5769e92984cb01d884e842f5af4d7e2b63d67f00d8c79482e51d01d5539e25"));

        // Test#2 for input of 64 bytes
        add("AES//NoPadding",
            hexToBytes("b2dbfeee7b903440008878fd0904321ed40868485825b182c65b991f9ab3f2a7b0275dfdfff52c3b2a2e393f841b6a3b9a1debadb2806eaf46f0a4b2f6395314"),
            hexToBytes("fc8b46d04b11f6303eec1a2e35a64662"),
            hexToBytes("3d39ca887f8013f7c86623e0eaefa756207d8051936e60130f119428d2ead2cdbe430f363dd8a64c83130c6faa3059e57eb0fb61f3fb327a655e8680d16ae30f"));

        // Test#3 for input of 64 bytes
        add("AES//NoPadding",
            hexToBytes("200d337d873994cf2f62fe9d080b339ea241433e9ce80bdb8399fce823d971abc5834df25a4dee93dc90578df1ca3f079a718392970bafb7772850c65a1e3477"),
            hexToBytes("1464dc211049aab446322ece241f8fff"),
            hexToBytes("32ea70fcfe0afdcac2c9629927583be4caa132160f7da24089f5abdb5585be3b8ad54bcc2cbc6a53ce51ce870fcbbdbf9270281aad0a0da6f208f43db4eadfd5"));

        // Test#4 for input of 64 bytes
        add("AES//NoPadding",
            hexToBytes("5ab4b950c78631eb09d344f9c4bfecf5f2a6d73b8e9f728214f9039a598cf98e0b9f21199339449711c04c07f5aa54a69548ae23b700e46db6ccf9c1c989609b"),
            hexToBytes("f1a7529e6ff8f4c8aa06084f5f7d5985"),
            hexToBytes("dbb9a49f7bd794addccd51dd0058a33d38984886e56f08999b79f6dad7894e8adeb520b1c7a8bb0df86b744d4fd7491998191f5d087e01b1f8293d7a387b5cb3"));

        // Test#0 for input of 16 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("fd538408414a006b699c8063634f61be"),
            hexToBytes("d2c8296e7f7c5aabea84446da9447d99"),
            hexToBytes("a659cf47be58b7aa7247152eac5fd9f6"),
            hexToBytes("84c7871379cb5f4b1a3a4b83a65baeea"));

        // Test#1 for input of 16 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("9d224e70fa5c014d69d77fbdbe7be6c3"),
            hexToBytes("77768cae3cd99f0f80cc797ada777bbf"),
            hexToBytes("aad1cd77a9e12cc7675887dab6e79516"),
            hexToBytes("2e3a41edddc70367b52ea947d4e43c8e"));

        // Test#2 for input of 16 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("597adfc359ca8a85d032e8672151a012"),
            hexToBytes("b6fc4b0b910b9c610676eac24df824e5"),
            hexToBytes("cc75c91e571faec59a2c66a511a21f43"),
            hexToBytes("ba4df4768c29c6041979f3576ac1782c"));

        // Test#3 for input of 16 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("1fcb4ee3441cef70b8f7a8a1da8fe5fb"),
            hexToBytes("e14234768f85e016589c890bb5bce31a"),
            hexToBytes("5e9394486db9a2aa3a6188da55b1cbb6"),
            hexToBytes("37628d0b7d50a4c22ead90cf8c6ecf5d"));

        // Test#4 for input of 16 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("79bbfd67bab9f29ce6af9eeaa3f1b051"),
            hexToBytes("97e927f13240890d81d0308fa0c25d4b"),
            hexToBytes("db18d88edf3a747f6138088ee5466e1e"),
            hexToBytes("e5906c5d5c291acb92ea89c28eae5d80"));

        // Test#0 for input of 32 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("1ee0ecf15fff1fd8389519b4745e1c9be071b16f77dc0a6e3c73bb70b88740aa"),
            hexToBytes("f9ab0180c744da4fd89e99c551710959"),
            hexToBytes("b281f3eda52aef737560db288c45c2a5"),
            hexToBytes("174b9870fcfc8aafb18cb14f53537a88fe01c5021924e7c07c3e76640d45115b"));

        // Test#1 for input of 32 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("f70c98a289cc38c28191bd8074235472fe2f9c788f080a9f6bff05a0ac4caa49"),
            hexToBytes("fc6fe20c1cb3df12e0536c4a6fe2d66a"),
            hexToBytes("610cf7751a11389e46a5d62f7b66e1cb"),
            hexToBytes("13c1fb7b32771b6b400f4576d7cc780a485473f131e8dd467447707201571369"));

        // Test#2 for input of 32 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("bf1735804321e44fe3fd943ec36d1cb02986875512f3c31e9268502fd20d2911"),
            hexToBytes("2f3b34b24f62b18823585d824c127908"),
            hexToBytes("bcd597ecb5e2e33385fcaa4e650e8e62"),
            hexToBytes("46a19b64a23f946464774037b6db7c9fc67421e8c25b078ad919ebab3aac7254"));

        // Test#3 for input of 32 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("9b53df5995684d92814ab8739cb4850136746449d46525e337ada6571b0a9079"),
            hexToBytes("b02319bd29593c00eb94447cb11dc198"),
            hexToBytes("43f3c73c5c26555354e1c2af483e21f6"),
            hexToBytes("db445ea267ceda1db3944ec697daf83e1cecb5293b2d8214799b1fb746034515"));

        // Test#4 for input of 32 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("3baf6a16f127f46ed63b5ed7bd937e1084230b26144870b2b1b53d817d9d604e"),
            hexToBytes("711298e8b074e613255e16862448904b"),
            hexToBytes("0a5e21573ab6395d40a854f8db806c2b"),
            hexToBytes("6309384d6ba40c141a10ae8ee0b7ebe17cc5a6ba9f1898e628b0cf39f4238f68"));

        // Test#0 for input of 64 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("a959ad9a8e50ae8516859c65791ac4ac20b1d7bc5b2f90d8f8ee19cdd59e765b311c0eda84bd67d5f186eca67b828696963380207d8239a011ef7b85d15fda07"),
            hexToBytes("3e71b6c38dbd6141e6e5b1f4b393a1de"),
            hexToBytes("53411d111ad218415df3df9e70f9dfe6"),
            hexToBytes("8a9763d971a5a8390b520eeb555f5eccb350dc6be18ad4bdcf38a2337937cbfe60bc17faa3d37e366cf97636ed6b19064c921ada264afec3ba08501e32d32493"));

        // Test#1 for input of 64 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("783e8322b546a4755b0274d6e1f01559dbbb130ab002f3adf2ad70899f4920d842a1ad4ca5ae26800356a748b096a8baa3c79b9e32ebeb667488afb728aea439"),
            hexToBytes("beabebc88a6a0ec51c8902ed6b250f1b"),
            hexToBytes("0144a9a31f3e40e22a313831f68b5586"),
            hexToBytes("33b4db76288292b0fed49fb09018432bb3915e875ad83a182a9ba75c7c4d2b5ecf8d7ccfa4d25df917dcf9892974f9fcbdbef5fc77e85d83b3d9b7260712e40f"));

        // Test#2 for input of 64 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("d58aef4dbb5731c7f19814e7c74d0ae977b8fecffabfcc59b88b001f9f7267e6e4d556f3fe9e4e71d5f004bfcc256e70911bdc394abc8f3ed2ffe1a47e5036a6"),
            hexToBytes("73cd6781693b382a563aaae380bc3056"),
            hexToBytes("e7669042822ccc4719d00eebcaa26fc4"),
            hexToBytes("4207c13c99b2277c819ee127e6dc8731171a6963cd402a003ae916f300a80321975fc3add70107286d2f618563bfe16a21e56eb09c5c6299c9d2c77ebeb248a0"));

        // Test#3 for input of 64 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("5e95be782a4796bfab2297398dc272c549350b896411b71235e5f44a98c15250ad79160c7cb36b0ba57b5ce66cbb80bcb2139786da6e5e9140666d36f7c7905c"),
            hexToBytes("83981b95e3375e57e2165d2113c0e1ad"),
            hexToBytes("f798fcdcd0ab2208045e330ead278758"),
            hexToBytes("68efc80b0f0d0b5c693947ea4f5170d2822ec44abfebb11ca6e4cdc64f8467e2837066f1c25676d1c1cc66c2559c9fede855a77805e76150bb2ab8ba0d89f88d"));

        // Test#4 for input of 64 bytes
        add("AES/CBC/NoPadding",
            hexToBytes("5d3b4ddc32798b03c360c80266fbce6c2391e969bd967bd5b3a4a3afd7c6d1111a609234b980b7955764acefc93a2d24e4ad9f44bc621f2b4eed1043bddb982c"),
            hexToBytes("cd2be8d8ec2c9c871c8eee5ba64a4099"),
            hexToBytes("39983bec197a8381c2938ba3ceb1bf27"),
            hexToBytes("8bb8c5117746cb0f23fe5736dde83353ea46743191eca3ce023c1bb8c35124c733ed67ccb543f25e6281821ef3a6a6c75dcef1bd1600a4945ed91b8da84aab30"));

          // RFC3602 test vectors
          // Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key
          add("AES/CBC/NoPadding",
              asciiToBytes("Single block msg"),
              hexToBytes("06a9214036b8a15b512e03d534120006"),    
              hexToBytes("3dafba429d9eb430b422da802c9fac41"),
              hexToBytes("e353779c1079aeb82708942dbe77181a"));
          
          // Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key
          add("AES/CBC/NoPadding",
              // Plaintext
              hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
              // Key
              hexToBytes("c286696d887c9aa0611bbb3e2025a45a"),
              // IV
              hexToBytes("562e17996d093d28ddb3ba695a2e6f58"),
              // Ciphertext
              hexToBytes("d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1"));
          
          // RFC3686 AES CTR mode test vectors
          // Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key
          add("AES/CTR/NoPadding",
              // Plaintext
              asciiToBytes("Single block msg"),
              // Key
              hexToBytes("AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E"),
              // IV
              hexToBytes("00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01"), 
              // Ciphertext
              hexToBytes("E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8"));  
                   
          // Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key          
          add("AES/CTR/NoPadding",
              // Plaintext
              hexToBytes("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" +
                         "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"),                          
              // Key
              hexToBytes("7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63"),
              // IV
              hexToBytes("00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01"),                  
              // Ciphertext
              hexToBytes("51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88" +
                         "EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28"));
          
          // PKCS#5 Padding Test vectors
          // Test#0 for input of 6 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("f6cee5ff28fd"),
              hexToBytes("ac5800ac3cb59c7c14f36019e43b44fe"),
              hexToBytes("f013ce1ec901b5b60a85a986b3b72eba"),
              hexToBytes("e8a846fd9718507371604504d4ca1ac7"));

          // Test#0 for input of 7 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("76cdfdf52a9753"),
              hexToBytes("24c4328aeffc0ca354a3215a3da23a38"),
              hexToBytes("c43c6269bb8c1dbba3bc22b7ba7e24b1"),
              hexToBytes("009e935f3fe4d57b57fc3127a8873d8c"));

          // Test#0 for input of 8 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("b103c928531d8875"),
              hexToBytes("4035227440a779dbd1ed75c6ae78cef5"),
              hexToBytes("8faff161a5ec06e051066a571d1729d9"),
              hexToBytes("b3d8df2c3147b0752a7e6bbbcc9d5758"));

          // Test#0 for input of 9 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("590b10224087872724"),
              hexToBytes("507008732ea559915e5e45d9710e3ed2"),
              hexToBytes("342b22c1cbf1c92b8e63a38de99ffb09"),
              hexToBytes("c11a034ed324aeae9cd5857ae4cd776f"));

          // Test#0 for input of 10 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("ccecfa22708b6d06439c"),
              hexToBytes("a060441b1b7cc2af405be4f6f5c58e22"),
              hexToBytes("429d3240207e77e9b9dade05426fe3cb"),
              hexToBytes("b61ff0a956b420347daa25bb76964b51"));

          // Test#0 for input of 11 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("8ff539940bae985f2f88f3"),
              hexToBytes("721888e260b8925fe51183b88d65fb17"),
              hexToBytes("5308c58068cbc05a5461a43bf744b61e"),
              hexToBytes("3ee8bdb21b00e0103ccbf9afb9b5bd9a"));

          // Test#0 for input of 12 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("4c84974b5b2109d5bc90e1f0"),
              hexToBytes("80ba985c93763f99ff4be6cdee6ab977"),
              hexToBytes("ca8e99719be2e842e81bf15c606bb916"),
              hexToBytes("3e087f92a998ad531e0ff8e996098382"));

          // Test#0 for input of 13 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("13eb26baf2b688574cadac6dba"),
              hexToBytes("1fe107d14dd8b152580f3dea8591fc3b"),
              hexToBytes("7b6070a896d41d227cc0cebbd92d797e"),
              hexToBytes("a4bfd6586344bcdef94f09d871ca8a16"));

          // Test#0 for input of 14 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("5fcb46a197ddf80a40f94dc21531"),
              hexToBytes("4d3dae5d9e19950f278b0dd4314e3768"),
              hexToBytes("80190b58666f15dbaf892cf0bceb2a50"),
              hexToBytes("2b166eae7a2edfea7a482e5f7377069e"));

          // Test#0 for input of 15 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("6842455a2992c2e5193056a5524075"),
              hexToBytes("0784fa652e733cb699f250b0df2c4b41"),
              hexToBytes("106519760fb3ef97e1ccea073b27122d"),
              hexToBytes("56a8e0c3ee3315f913693c0ca781e917"));

          // Test#0 for input of 16 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("c9a44f6f75e98ddbca7332167f5c45e3"),
              hexToBytes("04952c3fcf497a4d449c41e8730c5d9a"),
              hexToBytes("53549bf7d5553b727458c1abaf0ba167"),
              hexToBytes("7fa290322ca7a1a04b61a1147ff20fe66fde58510a1d0289d11c0ddf6f4decfd"));

          // Test#0 for input of 32 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("1ba93ee6f83752df47909585b3f28e56693f89e169d3093eee85175ea3a46cd3"),
              hexToBytes("2ae7081caebe54909820620a44a60a0f"),
              hexToBytes("fc5e783fbe7be12f58b1f025d82ada50"),
              hexToBytes("7944957a99e473e2c07eb496a83ec4e55db2fb44ebdd42bb611e0def29b23a73ac37eb0f4f5d86f090f3ddce3980425a"));

          // Test#0 for input of 33 bytes
          add("AES/CBC/PKCS5Padding",
              hexToBytes("0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d"),
              hexToBytes("898be9cc5004ed0fa6e117c9a3099d31"),
              hexToBytes("9dea7621945988f96491083849b068df"),
              hexToBytes("e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34"));

          add("AES/CBC/PKCS5Padding",
              asciiToBytes("{\"encrypt\" : \"foo\"}"),
              hexToBytes("dc28c4a23ec612dc63a23d32a5ecdaab"),
              hexToBytes("00000000000000000000000000000000"),              
              hexToBytes("c58c18a02297685e11148e51cbde72e644262e6bc875a3270f207f9e3936c1dd"));
        
    }        
}
