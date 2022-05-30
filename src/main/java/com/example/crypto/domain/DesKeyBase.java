package com.example.crypto.domain;

import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import com.example.crypto.util.Des;

public abstract class DesKeyBase implements DesKeyInterface {

	private byte[] key;
	private SecretKey secretKey;
	private byte[] kcv;
	private Cipher encryptCipher;
	private Cipher decryptCipher;
	
	protected DesKeyBase() {
	}

	@Override
	public byte[] toBytes() {
		return key;
	}

	@Override
	public String toHexString() {
		return Des.toHexString(key);
	}

	@Override
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

	@Override
	public String getKcvHexString() {
		return Des.toHexString(getKcv());
	}

	@Override
	public SecretKey getSecretKey() {
		return secretKey;
	}

	@Override
	public byte[] getSecretKeyBytes() {
		return secretKey.getEncoded();
	}

	@Override
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

	@Override
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

	protected void setKey(byte[] key) {
		this.key = key;
	}

	protected byte[] getKey() {
		return key;
	}

	protected void setSecretKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}
	
	protected SecretKey getSecretKey (KeySpec keySpec) {
		SecretKeyFactory factory = null;
		SecretKey key = null;
		
		try {
			factory = SecretKeyFactory.getInstance(getAlgorithm());
			key = factory.generateSecret(keySpec);
		} catch (Exception e) {
			// should never happen
			throw new RuntimeException(e);
		}
		
		return key;
	}

}
