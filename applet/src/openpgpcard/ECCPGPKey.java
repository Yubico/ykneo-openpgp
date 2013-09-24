package openpgpcard;

import javacard.framework.Util;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

public class ECCPGPKey extends PGPKey {
	private KeyPair key;
	private byte[] attributes;
	private byte[] oid;
	
	public static final byte CURVE_P256R1 = 1;
		
	public ECCPGPKey() {
		this(PGPKey.ALGO_ECDSA, CURVE_P256R1);
	}
	
	public ECCPGPKey(byte type, byte curve) {
		if(curve == CURVE_P256R1) {
			key = SecP256r1.newKeyPair();
			oid = SecP256r1.oid;
		}
		attributes = new byte[(short)(SecP256r1.oid.length + 1)];
		attributes[0] = type;
		Util.arrayCopyNonAtomic(SecP256r1.oid, (short)0, attributes, (short)1, (short) SecP256r1.oid.length);
	}

	public void genKeyPair() {
		key.genKeyPair();
	}

	public short getAttributes(byte[] data, short offset) {
		return Util.arrayCopy(attributes, (short)0, data, offset, (short) attributes.length);
	}

	public boolean isInitialized() {
		return key.getPrivate().isInitialized();
	}
	
	public short getPublicKey(byte[] data, short offset) {
		data[offset++] = 0x06;
		data[offset++] = (byte) oid.length;
		Util.arrayCopy(oid, (short)0, data, offset, (short) oid.length);
		offset += oid.length;
		data[offset++] = (byte) 0x86;
		ECPublicKey pubKey = getPublic();
		data[offset++] = 65; // XXX: for secp256r1 
		pubKey.getW(data, offset);
		return offset;
	}
	
	private ECPublicKey getPublic() {
		return (ECPublicKey) key.getPublic();
	}

	
	public void setPrivateKey(byte[] data, short offset) {
		// TODO Auto-generated method stub

	}

	
	public short decrypt(byte[] inData, short inOffs, short inLen,
			byte[] outData, short outOffs) {
		// TODO Auto-generated method stub
		return 0;
	}

	
	public short sign(byte[] inData, short inOffs, short inLen, byte[] outData,
			short outOffs) {
		// TODO Auto-generated method stub
		return 0;
	}

}
