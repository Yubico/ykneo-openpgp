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

import java.util.Arrays;

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
	static final byte[] success = {(byte) 0x90, 0x00};
	enum State {GOOD, BAD, BLOCKED};
	
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
		doVerify("123456", (byte) 0x81, State.GOOD);
	}
	
	@Test
	public void testBadVerify() {
		doVerify("654321", (byte) 0x81, State.BAD);
	}
	
	@Test
	public void testGenerate() {
		doVerify("12345678", (byte) 0x83, State.GOOD);
		byte[] command = {0x00, 0x47, (byte) 0x80, 0x00, 0x01, (byte) 0xb6};
		simulator.transmitCommand(command);
	}

	@Test
	public void testReset() {
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {2, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {1, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {0, 3, 3}, getPinRetries());
		doVerify("87654321", (byte) 0x83, State.BAD);
		assertArrayEquals(new byte[] {0, 3, 2}, getPinRetries());
		doVerify("87654321", (byte) 0x83, State.BAD);
		assertArrayEquals(new byte[] {0, 3, 1}, getPinRetries());
		doVerify("87654321", (byte) 0x83, State.BAD);
		assertArrayEquals(new byte[] {0, 3, 0}, getPinRetries());
		doVerify("123456", (byte) 0x81, State.BLOCKED);

		simulator.transmitCommand(new byte[] {0, (byte) 0xe6, 0, 0});
		simulator.transmitCommand(new byte[] {0, 0x44, 0, 0});

		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		doVerify("123456", (byte) 0x81, State.GOOD);
	}
	
	@Test
	public void testUnblock() {
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {2, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {1, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {0, 3, 3}, getPinRetries());
		doVerify("123456", (byte) 0x81, State.BLOCKED);

		doVerify("12345678", (byte) 0x83, State.GOOD);
		byte[] res = simulator.transmitCommand(new byte[] {0, 0x2c, 0x02, (byte) 0x81, 0x06,
				'6', '5', '4', '3', '2', '1'});
		assertArrayEquals(success,  res);
				
		doVerify("654321", (byte) 0x81, State.GOOD);
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
	}
	
	@Test
	public void testRcUnblock() {
		byte[] newRc = {0, (byte) 0xda, 0, (byte) 0xd3, 8, '8', '7', '6', '5', '4', '3', '2', '1'};
		doVerify("12345678", (byte) 0x83, State.GOOD);
		assertArrayEquals(success, simulator.transmitCommand(newRc));
		simulator.reset();
		simulator.selectApplet(aid);
		
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {2, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {1, 3, 3}, getPinRetries());
		doVerify("654321", (byte) 0x81, State.BAD);
		assertArrayEquals(new byte[] {0, 3, 3}, getPinRetries());
		doVerify("123456", (byte) 0x81, State.BLOCKED);
		
		byte[] res = simulator.transmitCommand(new byte[] {0, 0x2c, 0, (byte) 0x81, 14,
				'8', '7', '6', '5', '4', '3', '2', '1',
				'6', '5', '4', '3', '2', '1'});
		assertArrayEquals(success, res);
		doVerify("654321", (byte) 0x81, State.GOOD);
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
	}

	@Test
	public void testSetPintries() {
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte) 0xf2, 0, 0, 3, 5, 5, 5});
		assertArrayEquals(new byte[] {0x69, (byte) 0x85}, resp);
		doVerify("12345678", (byte) 0x83, State.GOOD);
		resp = simulator.transmitCommand(new byte[] {0, (byte) 0xf2, 0, 0, 3, 5, 6, 7});
		//assertArrayEquals*success, resp); JCardSim gets very confused with this assert
		assertArrayEquals(new byte[] {5, 6, 7}, getPinRetries());
	}

	@Test
	public void testSetCertificate() {
		byte[] data = {0, (byte) 0xda, 0x7f, 0x21, 8, 1, 2, 3, 4, 5, 6, 7, 8};
		byte[] resp = simulator.transmitCommand(data);
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);
		doVerify("12345678", (byte) 0x83, State.GOOD);
		resp = simulator.transmitCommand(data);
		assertArrayEquals(success, resp);

		simulator.reset();
		simulator.selectApplet(aid);
		byte[] expect = {0x7f, 0x21, 8, 1, 2, 3, 4, 5, 6, 7, 8, (byte) 0x90, 0};
		resp = simulator.transmitCommand(new byte[] {0, (byte) 0xca, 0x7f, 0x21});
		assertArrayEquals(expect, resp);
	}

	@Test
	public void testSignWithoutPin() {
		doVerify("12345678", (byte) 0x83, State.GOOD);
		byte[] command = {0x00, 0x47, (byte) 0x80, 0x00, 0x01, (byte) 0xb6};
		simulator.transmitCommand(command);

		command = new byte[]{0x00, 0x2A, (byte) 0x9E, (byte) 0x9A, 0x23, 0x30,
				0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
				0x00, 0x04, 0x14, 0x17, 0x53, 0x5F, 0x4B, (byte) 0x91, 0x59,
				(byte) 0xF1, (byte) 0xA8, (byte) 0x9D, 0x69, (byte) 0xEB, 0x75,
				(byte) 0xE7, 0x5E, (byte) 0x9E, 0x20, 0x24, (byte) 0xEF, 0x48,
				(byte) 0xE9, 0x00};
		byte[] resp = simulator.transmitCommand(command); // do a sign without pin first, should fail
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);

		doVerify("123456", (byte) 0x82, State.GOOD); // now verify pin (mode 82)
		resp = simulator.transmitCommand(command); // still fail..
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);

		doVerify("123456", (byte) 0x81, State.GOOD); // now verify pin (mode 81)
		resp = simulator.transmitCommand(command); // should succeed
		assertEquals(257, resp.length);
	}

	@Test
	public void testDecipherWithoutPin() {
		doVerify("12345678", (byte) 0x83, State.GOOD);
		byte[] command = {0x00, 0x47, (byte) 0x80, 0x00, 0x01, (byte) 0xb8};
		simulator.transmitCommand(command);

		command = new byte[]{0x00, 0x2A, (byte) 0x80, (byte) 0x86, 0x23, 0x30,
				0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
				0x00, 0x04, 0x14, 0x17, 0x53, 0x5F, 0x4B, (byte) 0x91, 0x59,
				(byte) 0xF1, (byte) 0xA8, (byte) 0x9D, 0x69, (byte) 0xEB, 0x75,
				(byte) 0xE7, 0x5E, (byte) 0x9E, 0x20, 0x24, (byte) 0xEF, 0x48,
				(byte) 0xE9, 0x00};
		byte[] resp = simulator.transmitCommand(command); // do a decipher without pin first, should fail
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);

		doVerify("123456", (byte) 0x81, State.GOOD); // now verify pin (mode 81)
		resp = simulator.transmitCommand(command); // still fail..
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);

		doVerify("123456", (byte) 0x82, State.GOOD); // now verify pin (mode 82)
		resp = simulator.transmitCommand(command); // should (kindof) succeed
		assertArrayEquals(new byte[] {0x00, 0x05}, resp); // 0x05 means an exception is thrown because this can't be decrypted
	}

	@Test
	public void testAuthenticateWithoutPin() {
		doVerify("12345678", (byte) 0x83, State.GOOD);
		byte[] command = {0x00, 0x47, (byte) 0x80, 0x00, 0x01, (byte) 0xa4};
		simulator.transmitCommand(command);

		command = new byte[]{0x00, (byte) 0x88, 0x00, 0x00, 0x23, 0x30,
				0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
				0x00, 0x04, 0x14, 0x17, 0x53, 0x5F, 0x4B, (byte) 0x91, 0x59,
				(byte) 0xF1, (byte) 0xA8, (byte) 0x9D, 0x69, (byte) 0xEB, 0x75,
				(byte) 0xE7, 0x5E, (byte) 0x9E, 0x20, 0x24, (byte) 0xEF, 0x48,
				(byte) 0xE9, 0x00};
		byte[] resp = simulator.transmitCommand(command); // do an authenticate without pin first, should fail
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);

		doVerify("123456", (byte) 0x81, State.GOOD); // now verify pin (mode 81)
		resp = simulator.transmitCommand(command); // still fail..
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);

		doVerify("123456", (byte) 0x82, State.GOOD); // now verify pin (mode 82)
		resp = simulator.transmitCommand(command); // should succeed
		assertEquals(257, resp.length);
	}

	private void doVerify(String pin, byte mode, State state) {
		byte[] command = new byte[5 + pin.length()];
		command[1] = 0x20;
		command[3] = mode;
		command[4] = (byte) pin.length();
		int offs = 5;
		for(byte b : pin.getBytes()) {
			command[offs++] = b;
		}
		byte[] resp = simulator.transmitCommand(command);
		if(state == State.GOOD) {
			assertArrayEquals(new byte[] {(byte) 0x90, 0x00}, resp);
		} else if(state == State.BAD){
			assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);
		} else if(state == State.BLOCKED){
			assertArrayEquals(new byte[] {0x69, (byte) 0x83}, resp);
		}
	}
	
	private byte[] getPinRetries() {
		byte[] result = new byte[3];
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte) 0xca, 0, 0x6e});
		byte[] code = Arrays.copyOfRange(resp, resp.length - 2, resp.length);
		assertArrayEquals(success, code);
		short offs = 4;
		offs += resp[offs];
		offs += 3;
		offs += resp[offs];
		offs += 5;
		offs += resp[offs];
		offs += 2;
		offs += resp[offs];
		offs += 2;
		offs += resp[offs];
		offs += 2;
		offs += resp[offs];
		offs += 7;
		result[0] = resp[offs++];
		result[1] = resp[offs++];
		result[2] = resp[offs++];
		return result;
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
