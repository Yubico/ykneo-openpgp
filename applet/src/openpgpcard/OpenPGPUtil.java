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

public class OpenPGPUtil implements ISO7816 {
	
	/**
	 * Get length of TLV element.
	 * 
	 * @param data
	 *            Byte array
	 * @param offset
	 *            Offset within byte array containing first byte
	 * @return Length of value
	 */
	public static short getLength(byte[] data, short offset) {
		short len = 0;

		if ((data[offset] & (byte) 0x80) == (byte) 0x00) {
			len = data[offset];
		} else if ((data[offset] & (byte) 0x7F) == (byte) 0x01) {
			len = data[(short) (offset + 1)];
			len &= 0x00ff;
		} else if ((data[offset] & (byte) 0x7F) == (byte) 0x02) {
			len = Util.makeShort(data[(short) (offset + 1)], data[(short) (offset + 2)]);
		} else {
			ISOException.throwIt(SW_UNKNOWN);
		}

		return len;
	}
	
	/**
	 * Get number of bytes needed to represent length for TLV element.
	 * 
	 * @param length
	 *            Length of value
	 * @return Number of bytes needed to represent length
	 */
	public static short getLengthBytes(short length) {
		if (length <= 127)
			return 1;
		else if (length <= 255)
			return 2;
		else
			return 3;
	}
}
