package com.example.crypto.domain;

import java.security.InvalidKeyException;

import com.example.crypto.util.Des;

public class DesKeyFactory {
	
	public static DesKeyInterface generateKey(int lengthInBits) {
		if (lengthInBits == Des.KEY_LENGTH_BITS_SINGLE) {
			return new DesKeySingle();			
		}
		if (lengthInBits == Des.KEY_LENGTH_BITS_DOUBLE) {
			return new DesKeyDouble();			
		}
		return null;
	}

	public static DesKeyInterface getKey(byte [] keyBytes) throws InvalidKeyException {
		if (keyBytes.length == Des.KEY_LENGTH_BYTES_SINGLE) {
			return new DesKeySingle(keyBytes);
		}
		if (keyBytes.length == Des.KEY_LENGTH_BYTES_DOUBLE) {
			return new DesKeyDouble(keyBytes);
		}
		return null;
	}

	public static DesKeyInterface getKey(String keyHexString) throws InvalidKeyException {
		return getKey(Des.toByteArray(keyHexString));
	}

}
