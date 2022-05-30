//
//This is what we are writing tests for
//
//

package com.example.crypto.domain;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.DESKeySpec;

import com.example.crypto.util.Des;

/**
 * 
 * This class implements a DES key (8 bytes, 56 bits). The key must have odd parity.
 *
 */
public class DesKeySingle extends DesKeyBase implements DesKeyInterface {

	/**
	 * Class constructor that generates a valid DES key
	 */
	public DesKeySingle() {
		super();
		
		try {
			setSecretKey(KeyGenerator.getInstance(getAlgorithm()).generateKey());
			setKey(getSecretKey().getEncoded().clone());
		} catch (NoSuchAlgorithmException e) {
			// should never happen
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Class constructor that receives key value expressed as a hex string. <br><br>
	 * The input string must be 16 characters long and represent a key that has odd parity
	 * 
	 * @param keyHexString value of key
	 * @throws IllegalArgumentException if key is null, empty or not 16 hex characters long
	 * @throws InvalidKeyException if the key does not have odd parity
	 */
	public DesKeySingle(String keyHexString) throws IllegalArgumentException, InvalidKeyException {
		super();
		
		if (!keyHexString.matches("^[A-Fa-f0-8]{16}$")) {
			throw new IllegalArgumentException("keyHexString contains non-hex characters");
		}
		
		generateKey(Des.toByteArray(keyHexString));
	}
	
	/**
	 * Class constructor that receives key value expressed as a byte array. <br><br>
	 * The input byte array must be 8 bytes and have odd parity
	 * 
	 * @param keyBytes value of key
	 * @throws IllegalArgumentException if key is null, empty or not 8 bytes long
	 * @throws InvalidKeyException if the key does not have odd parity
	 */
	public DesKeySingle(byte[] keyBytes) throws IllegalArgumentException, InvalidKeyException {
		super();
		generateKey(keyBytes);
	}
	
	private void generateKey(byte[] keyBytes) throws InvalidKeyException {
		if (keyBytes == null) {
			throw new IllegalArgumentException("keyBytes is null");
		}
		
		if (keyBytes.length == 0) {
			throw new IllegalArgumentException("keyBytes is empty");
		}
		
		if (keyBytes.length != 8) {
			throw new IllegalArgumentException("keyBytes array must be 8 bytes in length");
		}
		
		if (!Des.hasOddParity(keyBytes)) {
			throw new InvalidKeyException("parity error (key must have odd parity)");
		}
		
		setKey(keyBytes.clone());		
		setSecretKey(getSecretKey(new DESKeySpec(keyBytes)));
	}

	
	@Override
	/**
	 * Gets the algorithm employed by the key
	 * 
	 * @return String algorithm literal (value "DES")
	 */
	public String getAlgorithm() {
		return Des.ALGORITHM_DES;
	}

}
