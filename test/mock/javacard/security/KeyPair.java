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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyPair {
	java.security.KeyPair pair = null;
	KeyPairGenerator generator;
	
    public KeyPair(byte algorithm, short keyLength) {
    	try {
			generator = KeyPairGenerator.getInstance("RSA");
	    	generator.initialize(2048);
	    } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public void genKeyPair() {
    	pair = generator.generateKeyPair();
    }
    
    public PublicKey getPublic() {
    	return new RSAPublicKeyImpl((RSAPublicKey)pair.getPublic());
    }
    
    public PrivateKey getPrivate() {
    	return new RSAPrivateKeyImpl((RSAPrivateKey)pair.getPrivate());
    }
}
