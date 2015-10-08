/**
 * Java Card implementation of the OpenPGP card
 * Copyright (C) 2011  Joeri de Ruiter <joeri@cs.ru.nl>
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

public class PGPKey implements ISO7816 {
	public static final short KEY_SIZE = 2048;// 2368;
	public static final short KEY_SIZE_BYTES = KEY_SIZE / 8;
	public static final short COMPONENT_BYTES = KEY_SIZE_BYTES / 2;
	public static final short EXPONENT_SIZE = 17;
	public static final short EXPONENT_SIZE_BYTES = 3;
	public static final short FP_SIZE = 20;

	private KeyPair key;
	private byte[] fp;
	private byte[] time = { 0x00, 0x00, 0x00, 0x00 };
	private byte[] attributes = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03 };
	private static byte[] tmpBuf;

	public PGPKey() {
		key = new KeyPair(KeyPair.ALG_RSA_CRT, KEY_SIZE);

		fp = new byte[FP_SIZE];
		Util.arrayFillNonAtomic(fp, (short) 0, (short) fp.length, (byte) 0);

		Util.setShort(attributes, (short) 1, KEY_SIZE);
		Util.setShort(attributes, (short) 3, EXPONENT_SIZE);

		if(tmpBuf == null) {
			tmpBuf = JCSystem.makeTransientByteArray((short) (KEY_SIZE_BYTES / 2), JCSystem.CLEAR_ON_DESELECT);
		}
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
	public RSAPublicKey getPublic() {
		return (RSAPublicKey) key.getPublic();
	}

	/**
	 * @return Private key of the key pair
	 */
	public RSAPrivateCrtKey getPrivate() {
		return (RSAPrivateCrtKey) key.getPrivate();
	}

	/**
	 * @return Length in bytes of the exponent
	 */
	public short getExponentLength() {
		// Fixed value of 65537 for exponent
		return EXPONENT_SIZE_BYTES;
	}

	/**
	 * @return Length in bytes of the modulus
	 */
	public short getModulusLength() {
		return KEY_SIZE_BYTES;
	}

	/**
	 * Sets the value of the DP1 parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input DP1 parameter data is copied into
	 * the internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setDP1(byte[] buffer, short offset, short length) {
		Util.arrayFillNonAtomic(tmpBuf, (short) 0, (short) tmpBuf.length, (byte) 0);
		Util.arrayCopyNonAtomic(buffer, offset, tmpBuf, (short) (COMPONENT_BYTES - length), length);
		((RSAPrivateCrtKey) key.getPrivate()).setDP1(tmpBuf, (short) 0, COMPONENT_BYTES);
	}

	/**
	 * Sets the value of the DQ1 parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input DQ1 parameter data is copied into
	 * the internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setDQ1(byte[] buffer, short offset, short length) {
		Util.arrayFillNonAtomic(tmpBuf, (short) 0, (short) tmpBuf.length, (byte) 0);
		Util.arrayCopyNonAtomic(buffer, offset, tmpBuf, (short) (COMPONENT_BYTES - length), length);
		((RSAPrivateCrtKey) key.getPrivate()).setDQ1(tmpBuf, (short) 0, COMPONENT_BYTES);
	}

	/**
	 * Sets the value of the P parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input P parameter data is copied into the
	 * internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setP(byte[] buffer, short offset, short length) {
		((RSAPrivateCrtKey) key.getPrivate()).setP(buffer, offset, length);
	}

	/**
	 * Sets the value of the PQ parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input PQ parameter data is copied into the
	 * internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setPQ(byte[] buffer, short offset, short length) {
		Util.arrayFillNonAtomic(tmpBuf, (short) 0, (short) tmpBuf.length, (byte) 0);
		Util.arrayCopyNonAtomic(buffer, offset, tmpBuf, (short) (COMPONENT_BYTES - length), length);
		((RSAPrivateCrtKey) key.getPrivate()).setPQ(tmpBuf, (short) 0, COMPONENT_BYTES);
	}

	/**
	 * Sets the value of the Q parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input Q parameter data is copied into the
	 * internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setQ(byte[] buffer, short offset, short length) {
		((RSAPrivateCrtKey) key.getPrivate()).setQ(buffer, offset, length);
	}

	/**
	 * Sets the value of the Exponent parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input Exponent parameter data is copied
	 * into the internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setExponent(byte[] buffer, short offset, short length) {
		((RSAPublicKey) key.getPublic()).setExponent(buffer, offset, length);
	}

	/**
	 * Sets the value of the Modulus parameter. The plain text data format is
	 * big-endian and right-aligned (the least significant bit is the least
	 * significant bit of last byte). Input Modulus parameter data is copied
	 * into the internal representation.
	 * 
	 * @param buffer
	 *            The input buffer
	 * @param offset
	 *            The offset into the input buffer at which the parameter value
	 *            begins
	 * @param length
	 *            The length of the parameter
	 */
	public void setModulus(byte[] buffer, short offset, short length) {
		((RSAPublicKey) key.getPublic()).setModulus(buffer, offset, length);
	}
}
