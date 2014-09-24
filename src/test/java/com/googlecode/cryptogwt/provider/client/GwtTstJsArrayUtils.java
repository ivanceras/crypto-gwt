package com.googlecode.cryptogwt.provider.client;

import java.util.Arrays;

import com.google.gwt.core.client.JsArrayInteger;
import com.googlecode.cryptogwt.provider.JsArrayUtils;

public class GwtTstJsArrayUtils extends CryptoGwtProviderGWTTestCase {
    
    public void testBytesToJsArrayIntegerAndBack() {        
        byte[] bytes = { (byte) 0xff, 0x00, 0x01, (byte) 0xc0, (byte) 0xff, 0x00, 0x01, (byte) 0xc0, };
        JsArrayInteger jsArray = JsArrayUtils.toJsArrayInteger(bytes, 0, bytes.length);
        assertTrue(Arrays.equals(bytes, JsArrayUtils.toByteArray(jsArray)));
    }
    
    public void testEmptyBytesToJsArrayIntegerAndBack() {        
        byte[] bytes = { };
        JsArrayInteger jsArray = JsArrayUtils.toJsArrayInteger(bytes, 0, bytes.length);
        assertTrue(Arrays.equals(bytes, JsArrayUtils.toByteArray(jsArray)));
    }

}
