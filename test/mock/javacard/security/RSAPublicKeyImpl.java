package javacard.security;

/*
* Copyright (C) 2013 Yubico AB
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

import java.security.Key;


public class RSAPublicKeyImpl implements RSAPublicCrtKey {
	java.security.interfaces.RSAPublicKey key;

	public RSAPublicKeyImpl(java.security.interfaces.RSAPublicKey public1) {
		key = public1;
	}

	public boolean isInitialized() {
		return true;
	}

	public byte[] getKey() {
		return key.getEncoded();
	}

	public short getModulus(byte[] buffer, short offset) {
		byte[] mod = key.getModulus().toByteArray();
		System.arraycopy(mod, 0, buffer, offset, mod.length);
		return (short) mod.length;
	}

	public short getExponent(byte[] buffer, short offset) {
		byte[] exp = key.getPublicExponent().toByteArray();
		System.arraycopy(exp, 0, buffer, offset, exp.length);
		return (short) exp.length;
	}

	public Key getMockKey() {
		return key;
	}
}
