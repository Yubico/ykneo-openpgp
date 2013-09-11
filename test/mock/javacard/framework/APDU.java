package javacard.framework;

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

import java.util.Arrays;

public final class APDU {
	static byte[] buffer;
	
	public APDU(byte[] buf) {
		buffer = buf;
	}
	
    public byte[] getBuffer() {
    	return buffer;
    }
    
    public static byte[] getCurrentAPDUBuffer() {
    	return buffer;
    }
    
    public short setIncomingAndReceive() {
        return (short) buffer.length;
    }
    
    public void setOutgoingAndSend(short bOff, short len) {
    	Arrays.fill(buffer, bOff + len, buffer.length, (byte)0);
    }
    
    public short setOutgoing() {
        return (short)0x00ff;
    }
    
    public void setOutgoingLength(short len) {
    }
    
    public void sendBytes(short bOff, short len) {
    	Arrays.fill(buffer, bOff + len, buffer.length, (byte)0);
    }
    
    public static short getOutBlockSize() {
        return (short)0x00ff;
    }
}
