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
import javacard.framework.AID;
import openpgpcard.OpenPGPApplet;

import org.junit.Before;
import org.junit.Test;

import com.licel.jcardsim.base.Simulator;

public class OpenPGPAppletTest {
	Simulator simulator;
	static final byte[] pgpAid = new byte[] {(byte) 0xd2, 0x76, 0x00, 0x01, 0x24,
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
	static final AID aid = new AID(pgpAid, (short)0, (byte)pgpAid.length);
	
	@Before
	public void setup() {
		byte[] params = new byte[pgpAid.length + 1];
		params[0] = (byte) pgpAid.length;
		System.arraycopy(pgpAid, 0, params, 1, pgpAid.length);
		
		simulator = new Simulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, OpenPGPApplet.class, params, (short)0, (byte) params.length);
		simulator.selectApplet(aid);
	}

	@Test
	public void testVerify() {
		assertEquals(true, doVerify("123456", (byte) 0x81));
	}
	
	@Test
	public void testGenerate() {
		assertEquals(true, doVerify("12345678", (byte) 0x83));
		byte[] command = {0x00, 0x47, (byte) 0x80, 0x00, 0x01, (byte) 0xb6};
		simulator.transmitCommand(command);
	}

	@Test
	public void testReset() {
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertEquals(false, doVerify("87654321", (byte) 0x83));
		assertEquals(false, doVerify("87654321", (byte) 0x83));
		assertEquals(false, doVerify("87654321", (byte) 0x83));
		assertEquals(false, doVerify("123456", (byte) 0x81));

		simulator.transmitCommand(new byte[] {0, (byte) 0xe6, 0, 0});
		simulator.transmitCommand(new byte[] {0, 0x44, 0, 0});

		assertEquals(true, doVerify("123456", (byte) 0x81));

	}

	private boolean doVerify(String pin, byte mode) {
		byte[] command = new byte[5 + pin.length()];
		command[1] = 0x20;
		command[3] = mode;
		command[4] = (byte) pin.length();
		int offs = 5;
		for(byte b : pin.getBytes()) {
			command[offs++] = b;
		}
		byte[] resp = simulator.transmitCommand(command);
		if(resp[0] == (byte)0x90 && resp[1] == 0x00) {
			return true;
		} else {
			return false;
		}
	}
	
	@SuppressWarnings("unused")
	private void dumpHex(byte[] data) {
		String out = "";
		for(byte b : data) {
			out += String.format("0x%02x ", b);
		}
		System.out.println(out);
	}
}
