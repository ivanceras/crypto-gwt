package com.googlecode.cryptogwt.provider.client;

import com.google.gwt.dom.client.Document;
import com.google.gwt.user.client.Event;
import com.google.gwt.user.client.Random;
import com.google.gwt.user.client.rpc.AsyncCallback;
import com.google.gwt.user.client.ui.RootPanel;
import java.security.Security;
import com.googlecode.cryptogwt.provider.CryptoGwtProvider;
import com.googlecode.cryptogwt.provider.EntropyListener;
import com.googlecode.cryptogwt.provider.EventEntropySource;
import com.googlecode.cryptogwt.provider.FortunaSecureRandom;

public class GwtTstEventEntropySource extends CryptoGwtProviderGWTTestCase {
    
    public void testEventEntropySource() {
        Security.addProvider(CryptoGwtProvider.INSTANCE);
        FortunaSecureRandom.getInstance().registerEntropySource(new EventEntropySource());
        final boolean[] success = new boolean[] { false };
        FortunaSecureRandom.getInstance().waitForEntropy(new EntropyListener() {
            int bitsToReserve = 128;

            public boolean onEntropyUpdate(double availableEntropyEstimate) {
                if (availableEntropyEstimate < bitsToReserve) return false;
                success[0] = true;
                FortunaSecureRandom.getInstance().reserveEntropy(bitsToReserve);
                return false;
            }
        });
        generateRandomEvents();
        assertTrue(success[0]);
    }

    private void generateRandomEvents() {
        int screenX = 0; int screenY = 0;
        int x = 320; int y = 240;
        for (int i=0; i < 60; i++) {
            int xDelta = Random.nextInt(11) - 5;
            int yDelta = Random.nextInt(11) - 5;
            screenX += xDelta;
            x += xDelta;
            screenY += yDelta;
            y += yDelta;
            
            switch(Random.nextInt(4)) {
            case 0:
                Event.fireNativePreviewEvent(Document.get().createMouseOverEvent(0, screenX, screenY, x, y, false, false, false, false, 0, RootPanel.getBodyElement()));
                break;
            case 1:
                Event.fireNativePreviewEvent(Document.get().createMouseOutEvent(0, screenX, screenY, x, y, false, false, false, false, 0, RootPanel.getBodyElement()));
                break;
            case 2:
                Event.fireNativePreviewEvent(Document.get().createMouseDownEvent(0, screenX, screenY, x, y, false, false, false, false, 0));
                break;
            case 3:
                Event.fireNativePreviewEvent(Document.get().createMouseUpEvent(0, screenX, screenY, x, y, false, false, false, false, 0));
                break;
            }
        }
    }
}
