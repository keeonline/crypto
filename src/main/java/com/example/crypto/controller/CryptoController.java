package com.example.crypto.controller;

import com.example.crypto.domain.EncryptedPinData;
import com.example.crypto.domain.PinData;
import com.example.crypto.domain.ReEncryptedPinData;
import com.example.crypto.service.PinService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptoController {

    private final String pin = "1234";
    private final String pan = "43219876543210987";
    private final String key1 = "02020202020202020404040404040404";
    private final String key2 = "04040404040404040202020202020202";

    public CryptoController() {
    }

    @GetMapping("/crypto/pin-data")
    ResponseEntity<PinData> generatePinData() {
        return ResponseEntity.ok().body(new PinData(pin,pan));
    }

    @GetMapping("/crypto/enc-pin-data")
    ResponseEntity<EncryptedPinData> encryptPinData() {
        PinService service = new PinService();
        return ResponseEntity.ok().body(service.encryptPinData(pin,pan,key1));
    }

    @GetMapping("/crypto/reenc-pin-data")
    ResponseEntity<ReEncryptedPinData> reEncryptPinData() {
        PinData pinData = new PinData(pin,pan);
        EncryptedPinData epd = new EncryptedPinData(pinData,key1);

        PinService service = new PinService();
        return ResponseEntity.ok().body(service.reEncryptPinData(epd, key2));
    }
    
    @GetMapping("/crypto/reenc-pin-data-same-key")
    ResponseEntity<ReEncryptedPinData> reEncryptPinDataSameKey() {
        PinData pinData = new PinData(pin,pan);
        EncryptedPinData epd = new EncryptedPinData(pinData,key1);

        PinService service = new PinService();
        return ResponseEntity.ok().body(service.reEncryptPinData(epd, key1));
    }
}