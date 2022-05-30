package com.example.crypto.domain;

import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import com.example.crypto.util.Des;

public class DesKeyDouble extends DesKeyBase {
	
	private DesKeySingle key1;
	private DesKeySingle key2;

	public DesKeyDouble() {
		try {
			KeyGenerator generator = KeyGenerator.getInstance(Des.ALGORITHM_DESEDE);
			SecretKey sk = generator.generateKey();
			// overwrite k3 with k1
			byte[] keyBytes = sk.getEncoded();
			for (int i=0 ; i<8 ; i++) {
				keyBytes[24-(8-i)] = keyBytes[i];
			}
			setKey(Arrays.copyOfRange(keyBytes, 0, 16));
			setSecretKey(getSecretKey(new DESKeySpec(keyBytes)));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public DesKeyDouble(String keyHexString) throws InvalidKeyException {
		this(Des.toByteArray(keyHexString));
	}
	
	public DesKeyDouble(byte[] keyBytes) throws InvalidKeyException {
		if (keyBytes == null) {
			throw new IllegalArgumentException("keyBytes is null");
		}
		
		if (keyBytes.length == 0) {
			throw new IllegalArgumentException("keyBytes is empty");
		}
		
		if (keyBytes.length != 16) {
			throw new IllegalArgumentException("keyBytes array must be 16 bytes in length");
		}
		
		if (!Des.hasOddParity(keyBytes)) {
			throw new InvalidKeyException("parity error (key must have odd parity)");
		}
		
		setKey(keyBytes.clone());
		
		byte[] k1k2k1 = new byte[24];
		
		for (int i=0 ; i<16 ; i++) {
			k1k2k1[i] = keyBytes[i];
		}
		
		for (int i=16 ; i<24 ; i++) {
			k1k2k1[i] = keyBytes[i-16];
		}

		setSecretKey(getSecretKey(new DESedeKeySpec(k1k2k1)));	
	}
	
	@Override
	public String getAlgorithm() {
		return Des.ALGORITHM_DESEDE;
	}

}
