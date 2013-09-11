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

public class OwnerPIN {
	byte limit;
	byte maxSize;
	
	byte tries = 0;
	boolean validated = false;
	
	byte[] pin;
	
    public OwnerPIN(byte tryLimit, byte maxPINSize) {
    	limit = tryLimit;
    	maxSize = maxPINSize;
    }
    
    public void update(byte[] pin, short offset, byte length) {
    	this.pin = new byte[length];
    	System.arraycopy(pin, offset, this.pin, 0, length);
    	validated = false;
    	tries = 0;
    }
    
    public byte getTriesRemaining() {
    	return (byte) (limit - tries);
    }
    
    public boolean check(byte[] pin, short offset, byte length) {
    	if(length != this.pin.length) {
    		return false;
    	}
    	
    	for(int i = 0; i < length; i++) {
    		if(this.pin[i] != pin[offset + i]) {
    			tries++;
    			return false;
    		}
    	}
    	tries = 0;
    	validated = true;
    	return true;
    }
    
    public boolean isValidated() {
    	return validated;
    }
    
    public void resetAndUnblock() {
    	tries = 0;
    	validated = false;
    }
}
