package com.example.crypto.util;

import java.math.BigInteger;
import java.util.Formatter;

public class Des {
	public static final String ALGORITHM_DES = "DES";
	public static final String ALGORITHM_DESEDE = "DESede";

	public static final int KEY_LENGTH_BITS_SINGLE = 56;
	public static final int KEY_LENGTH_BITS_DOUBLE = 112;
	public static final int KEY_LENGTH_BITS_TRIPLE = 168;
	public static final int KEY_LENGTH_BYTES_SINGLE = 8;
	public static final int KEY_LENGTH_BYTES_DOUBLE = 16;
	public static final int KEY_LENGTH_BYTES_TRIPLE = 24;
	
	public static final byte[] NULLS = new byte[]{0,0,0,0,0,0,0,0};

	public static String toHexString(byte [] bytes){
		if (bytes == null){
			return "";
		}
		
		String result;
				
		Formatter formatter = new Formatter();
		for (byte b : bytes) {
		    formatter.format("%02X", b);
		}
		
		result = formatter.toString();

		formatter.close();
		
		return result;
	}
	
	public static byte[] toByteArray(String hex){
		int hexLength = hex.length();
		int arrayLength;
		
		if ((hexLength % 2) != 0){
			hex = "0" + hex;
		}

		arrayLength = hexLength/2;
		
		// Java has no unsigned data types to handle values with the top bit set.
		byte[] bytes = new byte[arrayLength];
		short[] shorts = new short[arrayLength];
		
		for ( int i=0 ; i < arrayLength ; i++ ){
			String str = hex.substring(i*2,(i*2)+2);
			shorts[i] = new BigInteger(str,16).shortValueExact();
			bytes[i] = (byte)shorts[i];			
		}
				
		return bytes;
	}

	public static boolean hasOddParity(byte[] bytes){
		if (bytes == null){
			return false;
		}
		
		for (byte b : bytes) {
			int bits = 0;
			for (int i=0 ; i<8 ; i++){
				if (((int)b&(int)(1<<i)) > 0){
					bits++;
				}
			}
			if (bits%2 == 0){
				return false;
			}
		}
		
		return true;
	}
}
