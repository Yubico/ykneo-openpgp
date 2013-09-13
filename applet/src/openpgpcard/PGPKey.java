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
	public static final short FP_SIZE = 20;
	
	public static PGPKey getInstance() {
		// the default
		return new RSAPGPKey();
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
	public abstract short getFingerprint(byte[] data, short offset);
	public abstract short getTime(byte[] data, short offset);
	public abstract void setFingerprint(byte[] data, short offset);
	public abstract void setTime(byte[] data, short offset);
	public abstract short getPublicKey(byte[] data, short offset);
	public abstract void setPrivateKey(byte[] data, short offset);
	public abstract short decrypt(byte[] inData, short inOffs, short inLen, byte[] outData, short outOffs);
	public abstract short sign(byte[] inData, short inOffs, short inLen, byte[] outData, short outOffs);
}
