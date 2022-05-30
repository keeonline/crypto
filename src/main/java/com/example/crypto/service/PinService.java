package com.example.crypto.service;

import javax.crypto.Cipher;

import com.example.crypto.domain.DesKeyFactory;
import com.example.crypto.domain.DesKeyInterface;
import com.example.crypto.domain.EncryptedPinData;
import com.example.crypto.domain.PinData;
import com.example.crypto.domain.ReEncryptedPinData;
import com.example.crypto.util.Des;

public class PinService {

    public EncryptedPinData encryptPinData(String pin, String pan, String key) {    
        return new EncryptedPinData(new PinData(pin,pan), key);
    }

    public ReEncryptedPinData reEncryptPinData(EncryptedPinData encryptedPinData, String key) {
        String before = encryptedPinData.getEncryptedPinData();
        String beforeKey = encryptedPinData.getKey();
        String pinData = decrypt(before, beforeKey);
        String after = encrypt(pinData, key);

        return new ReEncryptedPinData(before, beforeKey, pinData, after, key);
    }

    private String encrypt(String data, String key) {
        String result = null;

        try {
            DesKeyInterface k = DesKeyFactory.getKey(key);
            Cipher cipher = k.getEncryptCipher();
            result = execute(Des.toByteArray(data), cipher);
        }
        catch (Exception e) {
            System.out.println(e);
        }

        return result;
    }

    private String decrypt(String data, String key) {
        String result = null;

        try {
            DesKeyInterface k = DesKeyFactory.getKey(key);
            Cipher cipher = k.getDecryptCipher();
            result = execute(Des.toByteArray(data), cipher);
        }
        catch (Exception e) {
            System.out.println(e);
        }

        return result;
    }

    private String execute(byte [] bytes, Cipher cipher) {
        String result = null;
    
        try {
            byte [] block = cipher.doFinal(bytes);
            result = Des.toHexString(block);
        }
        catch (Exception e) {
            System.out.println(e);
        }

        return result;
    }

}
