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

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 * @version $Revision: 12 $ by $Author: joeridr $
 *          $LastChangedDate: 2012-02-23 15:31:33 +0100 (tor, 23 feb 2012) $
 */
public class RSAPGPKey extends PGPKey {
	private KeyPair key;
	private byte[] fp;
	private byte[] time = { 0x00, 0x00, 0x00, 0x00 };
	private byte[] attributes = { 0x01, 0x00, 0x00, 0x00, 0x00, FORMAT_CRT_M };
	
	private static Cipher cipher = null;

	public static final short EXPONENT_SIZE_BYTES = 3;
	public static final byte FORMAT_CRT_M = 3;
	
	public RSAPGPKey() {
		this((short)2048, (short)17);
	}
	
	public RSAPGPKey(short key_size, short exponent_size) {
		key = new KeyPair(KeyPair.ALG_RSA_CRT, key_size);

		fp = new byte[FP_SIZE];
		
		if(cipher == null) {
			cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		}
		
		Util.arrayFillNonAtomic(fp, (short) 0, (short) fp.length, (byte) 0);

		Util.setShort(attributes, (short) 1, key_size);
		Util.setShort(attributes, (short) 3, exponent_size);
	}

	/**
	 * Generate the key pair.
	 */
	public void genKeyPair() {
		key.genKeyPair();
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

	/**
	 * Get the algorithm attributes for the key pair.
	 * 
	 * @param data
	 *            Byte array
	 * @param offset
	 *            Offset within byte array indicating first byte
	 */
	public short getAttributes(byte[] data, short offset) {
		Util.arrayCopyNonAtomic(attributes, (short) 0, data, offset,
				(short) attributes.length);
		return (short) (offset + attributes.length);
	}

	/**
	 * @return Public key of the key pair
	 */
	private RSAPublicKey getPublic() {
		return (RSAPublicKey) key.getPublic();
	}

	/**
	 * @return Private key of the key pair
	 */
	private RSAPrivateCrtKey getPrivate() {
		return (RSAPrivateCrtKey) key.getPrivate();
	}

	/**
	 * @return Length in bytes of the modulus
	 */
	private short getModulusLength() {
		return (short) (getPrivate().getSize() / 8);
	}

	public boolean isInitialized() {
		return getPrivate().isInitialized();
	}

	public short getPublicKey(byte[] data, short offset) {
		// 81 - Modulus
		data[offset++] = (byte) 0x81;

		// Length of modulus is always greater than 128 bytes
		if (getModulusLength() < 256) {
			data[offset++] = (byte) 0x81;
			data[offset++] = (byte) getModulusLength();
		} else {
			data[offset++] = (byte) 0x82;
			offset = Util.setShort(data, offset, getModulusLength());
		}
		getPublic().getModulus(data, offset);
		offset += getModulusLength();

		// 82 - Exponent
		data[offset++] = (byte) 0x82;
		data[offset++] = (byte) EXPONENT_SIZE_BYTES;
		getPublic().getExponent(data, offset);
		offset += EXPONENT_SIZE_BYTES;
		
		return offset;
	}

	public void setPrivateKey(byte[] data, short offset) {

		// Skip empty length of CRT
		offset++;

		// Check for tag 7F48
		if (data[offset++] != 0x7F || data[offset++] != 0x48)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_template = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_template);

		short offset_data = (short) (offset + len_template);
		
		if (data[offset++] != (byte) 0x91)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_e = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_e);

		if (data[offset++] != (byte) 0x92)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_p = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_p);

		if (data[offset++] != (byte) 0x93)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_q = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_q);

		if (data[offset++] != (byte) 0x94)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_pq = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_pq);

		if (data[offset++] != (byte) 0x95)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_dp1 = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_dp1);

		if (data[offset++] != (byte) 0x96)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_dq1 = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_dq1);

		if (data[offset++] != (byte) 0x97)
			ISOException.throwIt(SW_DATA_INVALID);
		short len_modulus = OpenPGPUtil.getLength(data, offset);
		offset += OpenPGPUtil.getLengthBytes(len_dq1);

		if (data[offset_data++] != 0x5F || data[offset_data++] != 0x48)
			ISOException.throwIt(SW_DATA_INVALID);
		offset_data += OpenPGPUtil.getLengthBytes(OpenPGPUtil.getLength(data, offset_data));

		getPublic().setExponent(data, offset_data, len_e);
		offset_data += len_e;

		getPrivate().setP(data, offset_data, len_p);
		offset_data += len_p;

		getPrivate().setQ(data, offset_data, len_q);
		offset_data += len_q;

		getPrivate().setPQ(data, offset_data, len_pq);
		offset_data += len_pq;

		getPrivate().setDP1(data, offset_data, len_dp1);
		offset_data += len_dp1;

		getPrivate().setDQ1(data, offset_data, len_dq1);
		offset_data += len_dq1;

		getPublic().setModulus(data, offset_data, len_modulus);
		offset_data += len_modulus;
	}

	public short decrypt(byte[] inData, short inOffs, short inLen,
			byte[] outData, short outOffs) {
		cipher.init(getPrivate(), Cipher.MODE_DECRYPT);
		return cipher.doFinal(inData, inOffs, inLen, outData, outOffs);
	}

	public short sign(byte[] inData, short inOffs, short inLen, byte[] outData,
			short outOffs) {
		cipher.init(getPrivate(), Cipher.MODE_ENCRYPT);
		return cipher.doFinal(inData, inOffs, inLen, outData, outOffs);
	}
}
