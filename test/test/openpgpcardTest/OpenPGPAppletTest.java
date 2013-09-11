package openpgpcardTest;

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import javacard.framework.APDU;

import openpgpcard.OpenPGPApplet;

import org.junit.Test;
import org.junit.Before;

public class OpenPGPAppletTest {
	OpenPGPApplet openPGPApplet;
	
	@Before
	public void setup() {
		openPGPApplet = new OpenPGPApplet();
	}

	@Test
	public void testVerify() {
		byte[] buf = new byte[256];
		System.arraycopy(new byte[] {
				0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
		}, 0, buf, 0, 11);
		APDU apdu = new APDU(buf);
		openPGPApplet.process(apdu);
	}
}
