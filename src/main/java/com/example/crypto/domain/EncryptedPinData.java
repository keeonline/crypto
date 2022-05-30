package com.example.crypto.domain;

import javax.crypto.Cipher;

import com.example.crypto.util.Des;

public class EncryptedPinData {
    private PinData pinData;
    private String key;
    private String encryptedPinData;

    public EncryptedPinData(PinData pinData, String key) {
        this.pinData = pinData;
        this.key = key;

        try {
            DesKeyInterface k = DesKeyFactory.getKey(key);
            Cipher cipher = k.getEncryptCipher();
            byte [] encrypted = cipher.doFinal(pinData.getBytes());
            encryptedPinData = Des.toHexString(encrypted);
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

    public String getEncryptedPinData() {
        return encryptedPinData;
    }

    public PinData getPinData() {
        return pinData;
    }

    public String getKey() {
        return key;
    }

}