package com.example.crypto.domain;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import com.example.crypto.util.Des;

public final class DesKey {
	
	public static final String ALGORITHM_DES = "DES";
	public static final String ALGORITHM_DESEDE = "DESede";
		
	private byte[] key;
	private byte[] kcv;
	private SecretKey secretKey;
	private Cipher encryptCipher;
	private Cipher decryptCipher;
	
	public DesKey(int keyLength) {
		switch (keyLength) {
		case 56:
		{
			try {
				secretKey = KeyGenerator.getInstance(ALGORITHM_DES).generateKey();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
			break;
		}
		case 112:
		{
			try {
				KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM_DESEDE);
				SecretKey sk = generator.generateKey();
				byte[] keyBytes = sk.getEncoded();
				for (int i=0 ; i<8 ; i++) {
					keyBytes[24-(8-i)] = keyBytes[i];
				}
				SecretKeyFactory factory= getSecretKeyFactory(ALGORITHM_DESEDE);
				KeySpec keySpec = new DESedeKeySpec(keyBytes);
				secretKey = getSecretKey(factory,keySpec);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
			break;
		}
		case 168:
		{
			try {
				secretKey = KeyGenerator.getInstance(ALGORITHM_DESEDE).generateKey();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
			break;
		}
		default:
			throw new IllegalArgumentException("keyLength value must be one of 56, 112 or 168 (bits)");
		}
	}

	public DesKey(String keyString) throws InvalidKeyException {
		this(Des.toByteArray(keyString));
	}
	
	public DesKey(byte[] keyBytes) throws InvalidKeyException {
		if (keyBytes == null) {
			throw new IllegalArgumentException("keyBytes is null");
		}
		
		if (keyBytes.length == 0) {
			throw new IllegalArgumentException("keyBytes is empty");
		}
		
		switch (keyBytes.length) {
		case 8:
		case 16:
		case 24:
			break;
		default:
			throw new IllegalArgumentException("keyBytes array must be one of 8, 16 or 24 bytes in length");
		}
		
		if (!Des.hasOddParity(keyBytes)) {
			throw new InvalidKeyException("parity error (key must have odd parity)");
		}
		
		this.key = keyBytes.clone();
		
		SecretKeyFactory factory = null;
		KeySpec keySpec = null;;
		
		switch (keyBytes.length) {
		case 8:
			factory = getSecretKeyFactory(ALGORITHM_DES);
			keySpec = new DESKeySpec(keyBytes);
			break;
		case 16:
			byte[] k1k2k1 = new byte[24];
			for (int i=0 ; i<16 ; i++) {
				k1k2k1[i] = keyBytes[i];
			}
			for (int i=16 ; i<24 ; i++) {
				k1k2k1[i] = keyBytes[i-16];
			}
			factory = getSecretKeyFactory(ALGORITHM_DESEDE);
			keySpec = new DESedeKeySpec(k1k2k1);
			break;
		case 24:
			factory = getSecretKeyFactory(ALGORITHM_DESEDE);
			keySpec = new DESedeKeySpec(keyBytes);
			break;
		}
		
		secretKey = getSecretKey(factory,keySpec);		
	}
	
	private SecretKeyFactory getSecretKeyFactory (String algorithm) {
		SecretKeyFactory factory = null;
		
		try {
			factory = SecretKeyFactory.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return factory;
	}
	
	private SecretKey getSecretKey (SecretKeyFactory factory, KeySpec keySpec) {
		SecretKey key = null;
		
		try {
			key = factory.generateSecret(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		return key;
	}
	
	public SecretKey getSecretKey() {
		return secretKey;
	}
	
	public Cipher getEncryptCipher() {
		if (encryptCipher == null) {
			try {
				encryptCipher = Cipher.getInstance(secretKey.getAlgorithm() + "/ECB/NoPadding");
				encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);		
			} catch (Exception e) {
				// only coding error can produce exception - throw unhandled exception
				throw new RuntimeException(e);
			}
		}
		return encryptCipher;
	}
	
	public Cipher getDecryptCipher() {
		if (decryptCipher == null) {
			try {
				decryptCipher = Cipher.getInstance(secretKey.getAlgorithm() + "/ECB/NoPadding");
				decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);		
			} catch (Exception e) {
				// only coding error can produce exception - throw unhandled exception
				throw new RuntimeException(e);
			}
		}
		return decryptCipher;
	}
	
	public byte[] getKcv() {
		if (kcv == null) {
			Cipher cipher = getEncryptCipher();
			try {
				kcv = cipher.doFinal(Des.NULLS);
			} catch (Exception e) {
				// only coding error can produce exception - throw unhandled exception
				throw new RuntimeException(e);
			}
		}
		return kcv;
	}
	
	public String getKcvString() {
		return Des.toHexString(getKcv());
	}

	public String getAlgorithm() {
		return secretKey.getAlgorithm();
	}

	public byte[] getSecretKeyEncoded() {
		return secretKey.getEncoded();
	}

	public String toHexString() {
		return Des.toHexString(key);
	}

	public byte[] toBytes() {
		return key;
	}

}
