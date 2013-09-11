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

public class Util {
	public static short setShort(byte[] buf, short off, short val) {
		buf[off] = (byte) (val >>> 8);
		buf[off + 1] = (byte) val;
		return (short) (off + 2);
	}
	
	public static short arrayCopyNonAtomic(byte[] src, short srcOff, byte[] dest, short destOff,
            short length) throws ArrayIndexOutOfBoundsException, NullPointerException {
		System.arraycopy(src, srcOff, dest, destOff, length);
		return (short) (destOff + length);
	}
	
	public static short arrayCopy(byte[] src, short srcOff, byte[] dest, short destOff, short length)
			throws ArrayIndexOutOfBoundsException, NullPointerException {
		System.arraycopy(src, srcOff, dest, destOff, length);
		return (short) (destOff + length);
	}
	
    public static short makeShort(byte b1, byte b2) {
        return (short) ((b1 << 8) + (b2 & 0xFF));
    }
    
    public static short arrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue) {
    	Arrays.fill(bArray, bOff, bOff + bLen, bValue);
    	return (short) (bOff + bLen);
    }
    
    public static byte arrayCompare(byte[] src, short srcOff, byte[] dest, short destOff, short length) {
    	if(srcOff + length > src.length || destOff + length > dest.length) {
    		throw new ArrayIndexOutOfBoundsException();
    	}
    	for(int i = 0; i < length; i++) {
    		short thisSrc = (short) (src[srcOff + i] & 0x00ff);
    		short thisDest = (short) (dest[destOff + i] & 0x00ff);
    		if(thisSrc > thisDest) {
    			return 1;
    		} else if(thisSrc < thisDest) {
    			return -1;
    		}
    	}
    	return 0;
    }
    
    public static final short getShort(byte[] bArray, short bOff) throws NullPointerException,
    ArrayIndexOutOfBoundsException {
    	return (short) (((bArray[bOff]) << 8) + ((bArray[(short) (bOff + 1)]) & 0xFF));
    }
}
