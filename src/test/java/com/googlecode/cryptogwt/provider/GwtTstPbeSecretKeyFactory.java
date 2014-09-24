package com.googlecode.cryptogwt.provider;

//import java.util.ArrayList;
//import java.util.Collection;
//import java.util.List;
//
//import com.google.gwt.user.client.rpc.AsyncCallback;
//import com.googlecode.cryptogwt.async.AsyncSecretKeyFactory;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import com.googlecode.cryptogwt.provider.client.CryptoGwtProviderGWTTestCase;
import com.googlecode.cryptogwt.tests.CryptoTestVector;
import com.googlecode.cryptogwt.tests.PbeSecretKeyFactoryTestVectors;
//import com.googlecode.future.Future;

import static com.googlecode.cryptogwt.tests.CryptoTestVectors.assertOutputEquals;
import static com.googlecode.cryptogwt.util.ByteArrayUtils.*;

public class GwtTstPbeSecretKeyFactory extends CryptoGwtProviderGWTTestCase {
    
    public void testPasswordBasedkeyDerivation() throws GeneralSecurityException {
        // Note: vector.key = password, vector.input = salt, vector.iv = iterations.
        for (String algorithm : PbeSecretKeyFactoryTestVectors.INSTANCE.getAlgorithms()) {
            for (CryptoTestVector vector : PbeSecretKeyFactoryTestVectors.INSTANCE.get(algorithm)) {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
                SecretKey result = factory.generateSecret(new PBEKeySpec(
                        toAsciiString(vector.key).toCharArray(),
                        vector.input,
                        toInteger(vector.iv),
                        vector.expectedOutput.length * 8));
                assertOutputEquals(vector.expectedOutput, result.getEncoded());
                
            }
        }
    }
    
//    public void testAsyncPasswordBasedkeyDerivation() throws GeneralSecurityException {
//        final List<Integer> nrTestsRemaining = new ArrayList<Integer>();
//        final Collection<Boolean> allTestsSubmitted = new ArrayList<Boolean>();        
//        // Note: vector.key = password, vector.input = salt, vector.iv = iterations.
//        for (String algorithm : PbeSecretKeyFactoryTestVectors.INSTANCE.getAlgorithms()) {           
//            List<CryptoTestVector> vectors = PbeSecretKeyFactoryTestVectors.INSTANCE.get(algorithm);           
//            nrTestsRemaining.add(vectors.size());
//            final int algorithmNr = nrTestsRemaining.size() - 1;
//            for (final CryptoTestVector vector : vectors) {
//                AsyncSecretKeyFactory factory = 
//                    AsyncSecretKeyFactory.getAsyncInstance(algorithm);
//                Future<SecretKey> result = factory.generateSecretAsync(new PBEKeySpec(
//                        toAsciiString(vector.key).toCharArray(),
//                        vector.input,
//                        toInteger(vector.iv),
//                        vector.expectedOutput.length * 8));
//                result.addCallback(new AsyncCallback<SecretKey>() {                    
//                    public void onSuccess(SecretKey result) {
//                        assertOutputEquals(vector.expectedOutput, result.getEncoded());
//                        checkIfAllTestsFinished();
//                    }
//
//                    private void checkIfAllTestsFinished() {
//                        if (allTestsSubmitted.isEmpty()) return;
//                        nrTestsRemaining.set(algorithmNr, nrTestsRemaining.get(algorithmNr) - 1);
//                        for (int remainingTests : nrTestsRemaining) {
//                            if (remainingTests > 0) return;
//                        }
//                        finishTest();
//                    }
//                    
//                    public void onFailure(Throwable caught) {
//                        AssertionError assertionFailed = new AssertionError("Failed");
//                        assertionFailed.initCause(caught);
//                        throw assertionFailed;                                
//                    }
//                });                
//            }
//        }
//        allTestsSubmitted.add(true);
//        delayTestFinish(60000);
//    }
    

}
