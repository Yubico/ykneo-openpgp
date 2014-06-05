/**
 * Java Card implementation of the OpenPGP card
 * Copyright (C) 2013  Yubico AB
 * Copyright (C) 2011  Joeri de Ruiter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package openpgpcard;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public abstract class PGPKey implements ISO7816 {
	public static final byte ALGO_RSA = 1;
	public static final byte ALGO_ECDH = 0x12;
	public static final byte ALGO_ECDSA = 0x13;

	public static final short FP_SIZE = 20;
	
	private byte[] fp;
	private byte[] time = { 0x00, 0x00, 0x00, 0x00 };
	
	public PGPKey() {
		fp = new byte[FP_SIZE];
		Util.arrayFillNonAtomic(fp, (short) 0, (short) fp.length, (byte) 0);
	}
	
	public static PGPKey getInstance(byte type) {
		if(type == ALGO_RSA) {
			return new RSAPGPKey();
		} else if(type == ALGO_ECDSA || type == ALGO_ECDH) {
			return new ECCPGPKey(type);
		}
		return null;
	}
	
	public static PGPKey getInstance(byte[] data, short offset) {
		byte algorithm = data[offset++];
		if(algorithm == ALGO_RSA) {
			short key_size = Util.getShort(data, offset);
			short exponent_size = Util.getShort(data, (short) (offset + 2));
			return new RSAPGPKey(key_size, exponent_size);
		} else {
			ISOException.throwIt(SW_WRONG_DATA);
		}
		// not reached..
		return null;
	}
	
	public abstract void genKeyPair();
	public abstract short getAttributes(byte[] data, short offset);
	public abstract boolean isInitialized();
	public abstract short getPublicKey(byte[] data, short offset);
	public abstract void setPrivateKey(byte[] data, short offset);
	public abstract short decrypt(byte[] inData, short inOffs, short inLen, byte[] outData, short outOffs);
	public abstract short sign(byte[] inData, short inOffs, short inLen, byte[] outData, short outOffs);
	
	/**
	 * Set the generation time for the key pair.
	 * 
	 * @param data
	 *            Byte array
	 * @param offset
	 *            Offset within byte array containing first byte
	 */
	public void setTime(byte[] data, short offset) {
		// Check whether there are enough bytes to copy
		if ((short) (offset + time.length) > data.length)
			ISOException.throwIt(SW_UNKNOWN);

		Util.arrayCopyNonAtomic(data, offset, time, (short) 0, (short) 4);
	}
	
	/**
	 * Set the fingerprint for the public key.
	 * 
	 * @param data
	 *            Byte array
	 * @param offset
	 *            Offset within byte array containing first byte
	 */
	public void setFingerprint(byte[] data, short offset) {
		// Check whether there are enough bytes to copy
		if ((short) (offset + fp.length) > data.length)
			ISOException.throwIt(SW_UNKNOWN);

		Util.arrayCopyNonAtomic(data, offset, fp, (short) 0, (short) fp.length);
	}



	/**
	 * Get the fingerprint for the public key.
	 * 
	 * @param data
	 *            Byte array
	 * @param offset
	 *            Offset within byte array indicating first byte
	 */
	public short getFingerprint(byte[] data, short offset) {
		Util.arrayCopyNonAtomic(fp, (short) 0, data, offset, (short) fp.length);
		return (short) (offset + fp.length);
	}

	/**
	 * Get the generation time for the key pair.
	 * 
	 * @param data
	 *            Byte array
	 * @param offset
	 *            Offset within byte array indicating first byte
	 */
	public short getTime(byte[] data, short offset) {
		Util.arrayCopyNonAtomic(time, (short) 0, data, offset,
				(short) time.length);
		return (short) (offset + time.length);
	}


}
