package com.googlecode.cryptogwt.provider.client;

import java.util.Arrays;

import com.google.gwt.user.client.DeferredCommand;
import com.google.gwt.user.client.IncrementalCommand;
import com.google.gwt.user.client.rpc.AsyncCallback;
import java.security.SecureRandom;
import java.security.Security;
import com.googlecode.cryptogwt.provider.CryptoGwtProvider;
import com.googlecode.cryptogwt.util.ByteArrayUtils;

import static java.security.SpecialMathFunction.*;
import static com.googlecode.cryptogwt.util.ByteArrayUtils.getBit;

public class GwtTstNistRandomNumberTests extends CryptoGwtProviderGWTTestCase {

    private static final int BITS_TO_GENERATE = 8 * 100;

    private static final double ALPHA = 0.001;

    interface RngStrategy {
        void generate(SecureRandom prng, int nrBits,
                final AsyncCallback<byte[]> callback);
    }

    RngStrategy singleBitRngStrategy = new RngStrategy() {

        public void generate(final SecureRandom prng, final int nrBits,
                final AsyncCallback<byte[]> callback) {
            final int chunkSize = 10;
            IncrementalCommand cmd = new IncrementalCommand() {
                int i = 0;
                byte[] result = new byte[nrBits / 8];

                public boolean execute() {
                    int endOfNextChunk = Math.min(i + chunkSize, nrBits);
                    for (; i < endOfNextChunk; i++) {
                        ByteArrayUtils.setBit(result, i, prng.next(1));
                    }
                    if (i < nrBits)
                        return true;
                    callback.onSuccess(result);
                    return false;
                }
            };
            DeferredCommand.addCommand(cmd);
        }
    };

    RngStrategy allAtOnceRngStrategy = new RngStrategy() {
        public void generate(final SecureRandom prng, int nrBits,
                AsyncCallback<byte[]> callback) {
            byte[] result = new byte[nrBits / 8];
            prng.nextBytes(result);
            callback.onSuccess(result);
        }
    };

    public static interface NistTest {
        String description();

        void test(byte[] epsilon);
    }

    private NistTest monoBitFrequencyTest = new NistTest() {
        public String description() {
            return "Mono-bit Frequency Test";
        }

        public void test(byte[] e) {
            // Simple test to see whether frequency of bits is predictable
            Security.addProvider(CryptoGwtProvider.INSTANCE);
            final int n = e.length * 8;
            final double SQRT_2 = 1.41421356237309504880;
            double sum = 0.0;
            for (int i = 0; i < n; i++) {
                sum += (2 * getBit(e, i)) - 1;
            }
            double result = (Math.abs(sum) / Math.sqrt(n));
            double p = erfc(result / SQRT_2);
            assertIsRandom(p);
        }
    };

    private NistTest blockFrequencyTest = new NistTest() {
        public String description() {
            return "Block Frequency Test";
        }

        public void test(byte[] e) {
            final int n = e.length * 8;
            final int M = 8;
            final int N = n / M;
            
            assert n >= 100;

            double blockSum = 0.0;
            double sum = 0.0;            
            for (int i = 0; i < N; i++) {
                blockSum = 0;
                for (int j = 0; j < M; j++) { 
                    blockSum += ByteArrayUtils.getBit(e, j+i*M);
                }
                double pi = blockSum / M;
                double v = pi - 0.5;
                sum += v * v;
            }

            double chiSquared = 4.0 * M * sum;
            double p = igamc(N / 2.0, chiSquared / 2.0);
            assertIsRandom(p);
        }
    };

    private NistTest longestRunOfOnes = new NistTest() {
        public String description() {
            return "Longest Run of Ones in a block";
        }

        public void test(byte[] e) {
            double p, chi2;
            double pi[] = new double[7];
            int run, v_n_obs, N, i, j, K, M;
            int V[] = new int[7];
            int nu[] = new int[] { 0, 0, 0, 0, 0, 0, 0 };
            int n = e.length * 8;
            if (n < 128) {
                throw new IllegalStateException("Number of bits to test: " + n
                        + " is not large enough. ");
            }

            if (n < 6272) {
                K = 3;
                M = 8;
                V[0] = 1;
                V[1] = 2;
                V[2] = 3;
                V[3] = 4;
                pi[0] = 0.21484375;
                pi[1] = 0.3671875;
                pi[2] = 0.23046875;
                pi[3] = 0.1875;
            } else if (n < 750000) {
                K = 5;
                M = 128;
                V[0] = 4;
                V[1] = 5;
                V[2] = 6;
                V[3] = 7;
                V[4] = 8;
                V[5] = 9;
                pi[0] = 0.1174035788;
                pi[1] = 0.242955959;
                pi[2] = 0.249363483;
                pi[3] = 0.17517706;
                pi[4] = 0.102701071;
                pi[5] = 0.112398847;
            } else {
                K = 6;
                M = 10000;
                V[0] = 10;
                V[1] = 11;
                V[2] = 12;
                V[3] = 13;
                V[4] = 14;
                V[5] = 15;
                V[6] = 16;
                pi[0] = 0.0882;
                pi[1] = 0.2092;
                pi[2] = 0.2483;
                pi[3] = 0.1933;
                pi[4] = 0.1208;
                pi[5] = 0.0675;
                pi[6] = 0.0727;
            }

            N = n / M;
            for (i = 0; i < N; i++) {
                v_n_obs = 0;
                run = 0;
                for (j = 0; j < M; j++) {
                    if (ByteArrayUtils.getBit(e, i * M + j) == 1) {
                        run++;
                        if (run > v_n_obs)
                            v_n_obs = run;
                    } else
                        run = 0;
                }
                if (v_n_obs < V[0])
                    nu[0]++;
                for (j = 0; j <= K; j++) {
                    if (v_n_obs == V[j])
                        nu[j]++;
                }
                if (v_n_obs > V[K])
                    nu[K]++;
            }

            chi2 = 0.0;
            for (i = 0; i <= K; i++)
                chi2 += ((nu[i] - N * pi[i]) * (nu[i] - N * pi[i]))
                / (N * pi[i]);

            p = igamc((K / 2.0), chi2 / 2.0);
            assertIsRandom(p);

        }
    };

    public NistTest approximateEntropy = new NistTest() {

        public String description() { return "Approximate Entropy Test"; }

        public void test(byte[] e) {
            int i, j, k, r, blockSize, seqLength, powLen, index;
            double sum, numOfBlocks, apen, chi_squared, p;
            double ApEn[] = new double[2];
            int P[];
            int n = e.length * 8;
            seqLength = n;
            r = 0;
            int m = 8;

            for ( blockSize=m; blockSize<=m+1; blockSize++ ) {
                if ( blockSize == 0 ) {
                    ApEn[0] = 0.00;
                    r++;
                }
                else {
                    numOfBlocks = seqLength;
                    powLen = (int)Math.pow(2, blockSize+1)-1;
                    P = new int[powLen]; 
                    for ( i=1; i<powLen-1; i++ )
                        P[i] = 0;
                    for ( i=0; i<numOfBlocks; i++ ) { /* COMPUTE FREQUENCY */
                        k = 1;
                        for ( j=0; j<blockSize; j++ ) {
                            k <<= 1;
                            if (ByteArrayUtils.getBit(e, (i + j) % seqLength) == 1) k++;
                        }
                        P[k-1]++;
                    }
                    /* DISPLAY FREQUENCY */
                    sum = 0.0;
                    index = (int)Math.pow(2, blockSize)-1;
                    for ( i=0; i<(int)Math.pow(2, blockSize); i++ ) {
                        if ( P[index] > 0 ) {
                            sum += P[index] * Math.log(P[index]/numOfBlocks);
                        }
                        index++;
                    }
                    sum /= numOfBlocks;
                    ApEn[r] = sum;
                    r++;                    
                }
            }
            apen = ApEn[0] - ApEn[1];

            chi_squared = 2.0*seqLength*(Math.log(2) - apen);
            p = igamc(Math.pow(2, m-1), chi_squared/2.0);
            assertIsRandom(p);
        }

    };

    private NistTest TESTS[] = new NistTest[] { 
            monoBitFrequencyTest,
            blockFrequencyTest,
            longestRunOfOnes,
            approximateEntropy
    };

    public RngStrategy STRATEGIES[] = new RngStrategy[] { singleBitRngStrategy,
            allAtOnceRngStrategy };

    public void testRunTests() {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        SecureRandom prng = new SecureRandom();
        final boolean[] isFinished = new boolean[STRATEGIES.length];
        Arrays.fill(isFinished, false);

        for (int i = 0; i < STRATEGIES.length; i++) {
            final int strategyNr = i;
            STRATEGIES[strategyNr].generate(prng, BITS_TO_GENERATE,
                    new AsyncCallback<byte[]>() {
                        public void onFailure(Throwable paramThrowable) {
                            assert false;
                        }

                        public void onSuccess(byte[] e) {
                            for (NistTest test : TESTS) {
                                test.test(e);
                            }
                            checkForFinishedTest(isFinished, strategyNr);
                        }

                        private void checkForFinishedTest(
                                final boolean[] isFinished, final int strategyNr) {
                            isFinished[strategyNr] = true;
                            for (boolean finishedState : isFinished) {
                                if (!finishedState)
                                    return;
                            }
                            finishTest();
                        }
                    });
        }
        delayTestFinish(240000);
    }

    private void assertIsRandom(double p) {
        assertFalse("Probability sequence is non-random (p=" + p + ") is less than alpha value " + ALPHA, p < ALPHA);
    }

}
