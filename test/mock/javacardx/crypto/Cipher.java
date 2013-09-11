package javacardx.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javacard.security.DESKeyImpl;
import javacard.security.RSAPrivateKeyImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class Cipher {
	private javax.crypto.Cipher cipher;
	
    public static final byte MODE_DECRYPT = 1;
    public static final byte MODE_ENCRYPT = 2;
    
    private String transform = "AES/ECB/NoPadding";
    private String algo = "AES";

	public static final Cipher getInstance(byte algorithm, boolean externalAccess) {
		return new Cipher();
	}

	public Cipher(byte[] rawKey) {
		Key key = new SecretKeySpec(rawKey, algo);
		localInit(key, javax.crypto.Cipher.ENCRYPT_MODE);
	}
	
	private void localInit(Key key, int mode) {
		try {
			cipher = javax.crypto.Cipher.getInstance(transform);
			cipher.init(mode, key);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public Cipher() {
		// TODO Auto-generated constructor stub
	}   

	public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
		try {
			short ret = (short) cipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
			return ret;
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return 0;
	}
	
	public void init(javacard.security.Key theKey, byte theMode) {
		if(theKey.getClass() == DESKeyImpl.class) {
			transform = "DESede/ECB/NoPadding";
			algo = "DESede";
		} else if(theKey.getClass() == RSAPrivateKeyImpl.class) {
			transform = "RSA/ECB/NoPadding";
			algo = "RSA";
		}
		
		int mode = javax.crypto.Cipher.ENCRYPT_MODE;
		if(theMode == MODE_DECRYPT) {
			mode = javax.crypto.Cipher.DECRYPT_MODE;
		}
		localInit(theKey.getMockKey(), mode);
	}
}
