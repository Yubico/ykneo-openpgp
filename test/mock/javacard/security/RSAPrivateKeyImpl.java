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

public class RSAPrivateKeyImpl implements RSAPrivateCrtKey {
	java.security.interfaces.RSAPrivateKey key;
	
	public RSAPrivateKeyImpl(java.security.interfaces.RSAPrivateKey private1) {
		key = private1;
	}

	public boolean isInitialized() {
		if(key != null) {
			return true;
		} else {
			return false;
		}
	}

	public byte[] getKey() {
		// TODO Auto-generated method stub
		return key.getEncoded();
	}

	public Key getMockKey() {
		return key;
	}
}
