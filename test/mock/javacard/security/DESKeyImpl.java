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

import javax.crypto.spec.SecretKeySpec;

public class DESKeyImpl implements DESKey {
	byte[] key = new byte[24];
	boolean inited = false;

	public byte getKey(byte[] keyData, short kOff) {
		System.arraycopy(key, 0, keyData, kOff, 24);
		return 24;
	}

	public void setKey(byte[] keyData, short kOff) {
		System.arraycopy(keyData, kOff, key, 0, 24);
		inited = true;
	}

	public boolean isInitialized() {
		return inited;
	}

	public byte[] getKey() {
		return key;
	}
	
	public Key getMockKey() {
		return new SecretKeySpec(key, "DESede");
	}
}
