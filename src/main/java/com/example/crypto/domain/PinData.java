package com.example.crypto.domain;

import com.example.crypto.util.Des;

public class PinData {

    // Note: PIN is assumers to be 4 digits.
    // Note: PIN data assumed to be ISO-0.

    private final String pan;   
    private final String pin;  
    private final String data; 
    private final byte [] bytes;

    public PinData(String pin, String pan) {
        this.pin = pin;
        this.pan = pan;
        int panLen = pan.length();
        String dataString = new String("04" + pin + "ffffffffff");
        bytes = Des.toByteArray(dataString);
        String panExtractStr = pan.substring(panLen-13,panLen-1);
        byte [] panExtract = Des.toByteArray(panExtractStr);
        for ( int i = 2 ; i < 8 ; i++ ) {
            bytes[i] = (byte) ((byte) bytes[i] ^ (byte) panExtract[i-2]); 
        }
        data = Des.toHexString(bytes);
    }

    public String getPin() {
        return pin;
    }

    public String getPan() {
        return pan;
    }

    public String getData() {
        return data;
    }

    public byte[] getBytes() {
        return bytes;
    }

}
