package com.example.crypto.domain;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public interface DesKeyInterface {
	
	byte[] toBytes();
	String toHexString();
	byte[] getKcv();
	String getKcvHexString();
	String getAlgorithm();
	SecretKey getSecretKey();
	byte[] getSecretKeyBytes();
	Cipher getEncryptCipher();
	Cipher getDecryptCipher();

}
