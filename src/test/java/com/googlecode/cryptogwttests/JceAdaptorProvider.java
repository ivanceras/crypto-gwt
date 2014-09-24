package com.googlecode.cryptogwttests;

import java.util.Collections;

import sun.security.provider.SHA;
import sun.security.provider.SHA2;

import java.security.Provider;
import com.googlecode.cryptogwt.util.SpiFactoryService;
import com.sun.crypto.provider.AESCipher;
import com.sun.crypto.provider.PBKDF2HmacSHA1Factory;
import com.sun.crypto.provider.HmacSHA1;

@SuppressWarnings("restriction")
public class JceAdaptorProvider extends Provider {

    public static Provider getInstance() { return new JceAdaptorProvider(); }
                
    private JceAdaptorProvider() {
        super("JCE-Adaptor", 1.0, "");
        Provider.Service sha256 = new SpiFactoryService(
                this, 
                "MessageDigest",               
                "SHA-256",
                SHA2.class.getName(),
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                new MessageDigestSpiFactory(SHA2.class));
        
        Provider.Service sha1 = new SpiFactoryService(
                this, 
                "MessageDigest",               
                "SHA1",
                SHA.class.getName(),
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                new MessageDigestSpiFactory(SHA.class));
        
        Provider.Service aes = new SpiFactoryService(
                this, 
                "Cipher",               
                "AES",
                AESCipher.class.getName(),
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                new CipherSpiFactory(AESCipher.class));
        
        Provider.Service prng = new SpiFactoryService(
                this, 
                "SecureRandom",               
                "SHA1PRNG",
                sun.security.provider.SecureRandom.class.getName(),
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                new SecureRandomSpiFactory(sun.security.provider.SecureRandom.class));
        
        Provider.Service pbkdf2WithHmacSha1 = new SpiFactoryService(
                this, 
                "SecretKeyFactory",               
                "PBKDF2WithHmacSHA1",
                PBKDF2HmacSHA1Factory.class.getName(),
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                new SecretKeyFactorySpiFactory(PBKDF2HmacSHA1Factory.class));
        
        String hmacSha256Impl = "com.sun.crypto.provider.HmacCore$HmacSHA256";
        Provider.Service hmacSha256 = new SpiFactoryService(
                this, 
                "Mac",               
                "HmacSHA256",
                hmacSha256Impl,
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                // Note HmacCore is protected
                new MacSpiFactory(getClassViaReflection(hmacSha256Impl,
                        javax.crypto.MacSpi.class)));
        
        Provider.Service hmacSha1 = new SpiFactoryService(
                this, 
                "Mac",               
                "HmacSHA1",
                HmacSHA1.class.getName(),
                Collections.<String>emptyList(),
                Collections.<String, String>emptyMap(),
                // Note HmacCore is protected
                new MacSpiFactory(HmacSHA1.class));

        
        putService(sha256);
        putService(sha1);
        putService(aes);
        putService(prng);
        putService(pbkdf2WithHmacSha1);
        putService(hmacSha256);
        putService(hmacSha1);
        
    }

    @SuppressWarnings("unchecked")
    private <T> Class<? extends T> getClassViaReflection(String className, 
            Class<T> type) {            
        try {
            return (Class<? extends T>) Class.forName(className);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Could not load Hmac class", e);
        }
    }
    
}
