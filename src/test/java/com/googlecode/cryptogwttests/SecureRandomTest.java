package com.googlecode.cryptogwttests;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.Assert.*;

import static java.security.SpecialMathFunction.*;

public class SecureRandomTest {
    
    private static final double ALPHA = 0.001;

    @BeforeClass
    public static void setUp() {
        Security.addProvider(JceAdaptorProvider.getInstance());
    }
    
    @Test
    public void canLoadDefaultInstance() {
        assertNotNull(new SecureRandom());
    }
    
    @Test
    public void canGenerateRandomInt() {
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
            if (random == 0) numberOfZeros++;
            assertTrue(numberOfZeros < MAX_NR_ZEROES);
        } while (random == 0);
            
        assertTrue((random & 0xffff0000) == 0);
        assertFalse((random & 0x0000ffff) == 0);
    }
    
    @Test
    public void testCanGenerateSingleBits() {        
        SecureRandom prng = new SecureRandom();
        int random;
        do {
            random = prng.next(1);            
        } while (random == 0);            
        assertEquals(1, random);
    }
    
    @Test
    public void canGenerateRandomNumberOfBytes() {
        SecureRandom prng = new SecureRandom();
        byte[] random = new byte[32];
        prng.nextBytes(random);
    }
    
    @Test(expected=NoSuchAlgorithmException.class)
    public void bogusAlgorithmThrowsException() throws NoSuchAlgorithmException {
       SecureRandom.getInstance("Bogus algorithm");
    }
    
    @Test
    public void nistFrequencyTest() {
        // Simple test to see whether frequency of bits is predictable
        int n = 1000000;        
        SecureRandom prng = new SecureRandom();
        double sum = 0.0;
        final double SQRT_2 = 1.41421356237309504880;
        for (int i = 0; i < n; i++) {
            int bit = prng.next(1);
            sum += (2 * bit) - 1;
        }
        double result = (Math.abs(sum)/Math.sqrt(n));        
        double p = erfc(result/SQRT_2);        
        assertTrue(p > ALPHA);
    }
    
    @Test
    public void nistBlockFrequencyTest() {
        // Simple test to see whether frequency of blocks of bits are predictable
        int n = 1000000/8;
        int M = 8;
        int N = n/M;
        double blockSum = 0.0;        
        double sum = 0.0;
        
        SecureRandom prng = new SecureRandom();
       
        for (int i=0; i<N; i++) {
            blockSum += prng.next(M);
            double pi = blockSum/M;
            double v = pi - 0.5;
            sum += v*v;
        }
        double chiSquared = 4.0 * M * sum;
        double p = igamc(N/2.0, chiSquared/2.0);
        assert(p < ALPHA);
    }
    
    

}
