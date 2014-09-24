package com.googlecode.cryptogwt.provider.client;

import org.junit.Test;

import com.google.gwt.user.client.Random;
import java.security.SecureRandom;
import java.security.Security;
import com.googlecode.cryptogwt.provider.CryptoGwtProvider;

public class GwtTstSecureRandom extends CryptoGwtProviderGWTTestCase {

    public void testCanLoadDefaultInstance() {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        assertNotNull(new SecureRandom());
    }
    
    public void testCanLoadDefaultInstanceAndSeedIt() {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        SecureRandom secureRandom = new SecureRandom();
        for (int i=0; i < 64; i++) {
            secureRandom.setSeed(Random.nextInt());
        }
    }

    public void testCanGenerateRandomInt() {
        SecureRandom prng = new SecureRandom();
        prng.nextInt();        
    }

    @Test
    public void canGenerateRandomNumberOfBits() {
        SecureRandom prng = new SecureRandom();
        int random;
        int numberOfZeros = 0;
        int MAX_NR_ZEROES = 4; /* p = 2^-64 */
        do {
            random = prng.next(16);
            if (random == 0)
                numberOfZeros++;
            assertTrue(numberOfZeros < MAX_NR_ZEROES);
        } while (random == 0);

        assertTrue((random & 0xffff0000) == 0);
        assertFalse((random & 0x0000ffff) == 0);
    }

    @Test
    public void testCanGenerateSingleBits() {
        SecureRandom prng = new SecureRandom();
        int random;
        int numberOfZeros = 0;
        int MAX_NR_ZEROES = 64; /* p = 2^-64 */
        do {
            random = prng.next(1);
            if (random == 0)
                numberOfZeros++;
            assertTrue(numberOfZeros < MAX_NR_ZEROES);
        } while (random == 0);
        assertEquals(1, random);
    }

    public void testCanGenerateRandomNumberOfBytes() {
        SecureRandom prng = new SecureRandom();
        byte[] random = new byte[32];
        prng.nextBytes(random);        
    }

}
