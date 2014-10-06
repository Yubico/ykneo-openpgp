/**
 * Java Card implementation of the OpenPGP card
 * 
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
 * 
 * OpenPGPSecureMessaging.java is based on OVSecureMessaging.java which is part
 * of OVchip-ng
 * 
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, February 2011.
 */

package openpgpcard;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * OV secure messaging functionality.
 * 
 * <p>OVSecureMessaging is based on PassportCrypto which is part of the
 * e-passport Java Card applet from the JMRTD project (http://jmrtd.org/).
 * 
 * @author Pim Vullers
 * @version $Revision: 12 $ by $Author: joeridr $
 *          $LastChangedDate: 2012-02-23 15:31:33 +0100 (tor, 23 feb 2012) $
 */
public class OpenPGPSecureMessaging {
    private static final short SW_INTERNAL_ERROR = (short) 0x6D66;
    private static final byte[] PAD_DATA = {(byte) 0x80, 0, 0, 0, 0, 0, 0, 0};
    private static final short SSC_SIZE = 8;
    private static final short TMP_SIZE = 256;
    private static final short MAC_SIZE = 8;
    private static final short KEY_SIZE = 16;
    private static final byte[] EMPTY_KEY = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    /**
     * The needed cryptographic functionality.
     */
    private Signature signer;
    private Signature verifier;
    private Cipher cipher;
    private Cipher decipher;

    /**
     * The needed keys.
     */
    private DESKey keyMAC;
    private DESKey keyENC;
    
    /**
     * The send sequence counter.
     */
    private byte[] ssc;
    
    /**
     * Storage for temporary data.
     */
    private byte[] tmp;
    
    private boolean[] ssc_set;
    
    /**
     * Construct a new secure messaging wrapper.
     */
    public OpenPGPSecureMessaging() {
        ssc = JCSystem.makeTransientByteArray(SSC_SIZE, 
                JCSystem.CLEAR_ON_DESELECT);
        tmp = JCSystem.makeTransientByteArray(TMP_SIZE, 
                JCSystem.CLEAR_ON_DESELECT);
        ssc_set = JCSystem.makeTransientBooleanArray((short)1,
                JCSystem.CLEAR_ON_DESELECT);

        signer = Signature.getInstance(
                Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        verifier = Signature.getInstance(
                Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        cipher = Cipher.getInstance(
                Cipher.ALG_DES_CBC_ISO9797_M2, false);
        decipher = Cipher.getInstance(
                Cipher.ALG_DES_CBC_ISO9797_M2, false);
        
        keyMAC = (DESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, 
                KeyBuilder.LENGTH_DES3_2KEY, false);
        keyENC = (DESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, 
                KeyBuilder.LENGTH_DES3_2KEY, false);
        
        init();
    }

    public void init() {
        ssc_set[0] = false;
        Util.arrayFillNonAtomic(ssc, (short)0, SSC_SIZE, (byte) 0);
        Util.arrayFillNonAtomic(tmp, (short)0, TMP_SIZE, (byte) 0);
        
        clearSessionKeys();
    }

    /**
     * Set the MAC and encryption (and decryption) session keys. Each key is a 
     * 16 byte 3DES EDE key. This method may be called at any time and will 
     * immediately replace the session key.
     * 
     * @param buffer byte array containing the session keys.
     * @param offset location of the session keys in the buffer.
     */
    public void setSessionKeys(byte[] buffer, short offset) {
    	// Check for empty keys
    	if(Util.arrayCompare(buffer, (short)0, EMPTY_KEY, (short)0, KEY_SIZE) == 0 ||
    			Util.arrayCompare(buffer, KEY_SIZE, EMPTY_KEY, (short)0, KEY_SIZE) == 0) {
    		keyMAC.clearKey();
    		keyENC.clearKey();
    	}
    	else {    	
    		keyMAC.setKey(buffer, offset);
    		keyENC.setKey(buffer, (short) (offset + KEY_SIZE));
        
    		signer.init(keyMAC, Signature.MODE_SIGN);
        	verifier.init(keyMAC, Signature.MODE_VERIFY);
        
        	cipher.init(keyENC, Cipher.MODE_ENCRYPT);
        	decipher.init(keyENC, Cipher.MODE_DECRYPT);
    	}
    }
    
    /**
     * Set the MAC session key. Each key is a 16 byte 3DES EDE key. This method 
     * may be called at any time and will immediately replace the session key.
     * 
     * @param buffer byte array containing the session key.
     * @param offset location of the session key in the buffer.
     */
    public void setSessionKeyMAC(byte[] buffer, short offset) {
    	// Check for empty keys
    	if(Util.arrayCompare(buffer, (short)0, EMPTY_KEY, (short)0, KEY_SIZE) == 0) {
    		keyMAC.clearKey();
    		keyENC.clearKey();
    	}
    	else {     	
    		keyMAC.setKey(buffer, offset);
        
    		signer.init(keyMAC, Signature.MODE_SIGN);
    		verifier.init(keyMAC, Signature.MODE_VERIFY);
    	}
    }

    /**
     * Set the encryption session key. Each key is a 16 byte 3DES EDE key. This method 
     * may be called at any time and will immediately replace the session key.
     * 
     * @param buffer byte array containing the session key.
     * @param offset location of the session key in the buffer.
     */
    public void setSessionKeyEncryption(byte[] buffer, short offset) {
    	// Check for empty keys
    	if(Util.arrayCompare(buffer, (short)0, EMPTY_KEY, (short)0, KEY_SIZE) == 0) {
    		keyMAC.clearKey();
    		keyENC.clearKey();
    	}
    	else {     	
    		keyENC.setKey(buffer, (short) (offset + KEY_SIZE));
        
    		cipher.init(keyENC, Cipher.MODE_ENCRYPT);
    		decipher.init(keyENC, Cipher.MODE_DECRYPT);
    	}
    }

    /**
     * Set the MAC and encryption (and decryption) 3DES session keys to zero.
     */
    public void clearSessionKeys() {
        keyMAC.clearKey();
        keyENC.clearKey();
    }
    
    /**
     * Unwraps (verify and decrypt) the command APDU located in the APDU buffer.
     * The command buffer has to be filled by the APDU.setIncomingAndReceive()
     * method beforehand. The verified and decrypted command data get placed at
     * the start of the APDU buffer.
     * 
     * @return the length value encoded by DO97, 0 if this object is missing.
     */
    public short unwrapCommandAPDU() {
        byte[] buf = APDU.getCurrentAPDUBuffer();
        short apdu_p = (short) (ISO7816.OFFSET_CDATA & 0xff);
        short start_p = apdu_p;
        short le = 0;
        short do87DataLen = 0;
        short do87Data_p = 0;
        short do87LenBytes = 0;
        short hdrLen = 4;
        short hdrPadLen = (short) (8 - hdrLen);

        incrementSSC();

        if (buf[apdu_p] == (byte) 0x87) {
            apdu_p++;
            // do87
            if ((buf[apdu_p] & 0xff) > 0x80) {
                do87LenBytes = (short) (buf[apdu_p] & 0x7f);
                apdu_p++;
            } else {
                do87LenBytes = 1;
            }
            if (do87LenBytes > 2) { // sanity check
                ISOException.throwIt(SW_INTERNAL_ERROR);
            }
            for (short i = 0; i < do87LenBytes; i++) {
                do87DataLen += (short) ((buf[(short)(apdu_p + i)] & 0xff) << (short) ((do87LenBytes - 1 - i) * 8));
            }
            apdu_p += do87LenBytes;

            if (buf[apdu_p] != 1) {
                ISOException.throwIt(SW_INTERNAL_ERROR);
            }
            // store pointer to data and defer decrypt to after mac check (do8e)
            do87Data_p = (short) (apdu_p + 1);
            apdu_p += do87DataLen;
            do87DataLen--; // compensate for 0x01 marker
        }

        if (buf[apdu_p] == (byte) 0x97) {
            // do97
            if (buf[++apdu_p] != 1)
                ISOException.throwIt(SW_INTERNAL_ERROR);
            le = (short) (buf[++apdu_p] & 0xff);
            apdu_p++;
        }

        // do8e
        if (buf[apdu_p] != (byte) 0x8e) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }
        if (buf[++apdu_p] != 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // verify mac
        verifier.update(ssc, (short)0, (short)ssc.length);
        verifier.update(buf, (short)0, hdrLen);
        verifier.update(PAD_DATA, (short)0, hdrPadLen);
        if (!verifier.verify(buf, start_p, (short) (apdu_p - 1 - start_p), buf, 
                (short)(apdu_p + 1), MAC_SIZE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short lc = 0;
        if (do87DataLen != 0) {
            // decrypt data, and leave room for lc
            lc = decipher.doFinal(buf, do87Data_p, do87DataLen, buf, 
                    (short) (hdrLen + 1));
            buf[hdrLen] = (byte) (lc & 0xff);
        }

        return le;
    }

    /**
     * Wraps (encrypts and build MAC) the response data and places it in the
     * APDU buffer starting at offset 0. The buffer can be any buffer including
     * the APDU buffer itself. If the length is zero the buffer will not be
     * addressed and no response data will be present in the wrapped output.
     * 
     * @param buffer byte array containing the data which needs to be wrapped.
     * @param offset location of the data in the buffer.
     * @param length of the data in the buffer (in bytes).
     * @param status word which has to be wrapped in the response APDU.
     * @return the length of the wrapped data in the <apdu> buffer
     */
    public short wrapResponseAPDU(byte[] buffer, short offset, short length, 
            short status) {
        byte[] apdu = APDU.getCurrentAPDUBuffer();
        short apdu_p = 0;
        // smallest multiple of 8 strictly larger than plaintextLen (length + padding)
        short do87DataLen = (short) ((((short) (length + 8)) / 8) * 8);
        // for 0x01 marker (indicating padding is used)
        do87DataLen++;
        short do87DataLenBytes = (short)(do87DataLen > 0xff? 2 : 1);
        short do87HeaderBytes = getApduBufferOffset(length);
        short do87Bytes = (short)(do87HeaderBytes + do87DataLen - 1); // 0x01 is counted twice 
        boolean hasDo87 = length > 0;

        incrementSSC();

        short ciphertextLength=0;
        if(hasDo87) {
            // Copy the plain text to temporary buffer to avoid data corruption.
            Util.arrayCopyNonAtomic(buffer, offset, tmp, (short) 0, length);
            // Put the cipher text in the proper position.
            ciphertextLength = cipher.doFinal(tmp, (short) 0, length, apdu, 
                    do87HeaderBytes);
        }
        //sanity check
        //note that this check
        //  (possiblyPaddedPlaintextLength != (short)(do87DataLen -1))
        //does not always hold because some algs do the padding in the final, some in the init.
        if (hasDo87 && (((short) (do87DataLen - 1) != ciphertextLength)))
            ISOException.throwIt(SW_INTERNAL_ERROR);
        
        if (hasDo87) {
            // build do87
            apdu[apdu_p++] = (byte) 0x87;
            if(do87DataLen < 0x80) {
                apdu[apdu_p++] = (byte)do87DataLen; 
            } else {
                apdu[apdu_p++] = (byte) (0x80 + do87DataLenBytes);
                for(short i = (short) (do87DataLenBytes - 1); i >= 0; i--) {
                    apdu[apdu_p++] = (byte) ((do87DataLen >>> (i * 8)) & 0xff);
                }
            }
            apdu[apdu_p++] = 0x01;
        }

        if(hasDo87) {
            apdu_p = do87Bytes;
        }
        
        // build do99
        apdu[apdu_p++] = (byte) 0x99;
        apdu[apdu_p++] = 0x02;
        Util.setShort(apdu, apdu_p, status);
        apdu_p += 2;

        // calculate and write mac
        signer.update(ssc, (short) 0, (short) ssc.length);
        signer.sign(apdu, (short) 0, apdu_p, apdu, (short) (apdu_p + 2));

        // write do8e
        apdu[apdu_p++] = (byte) 0x8e;
        apdu[apdu_p++] = 0x08;
        apdu_p += 8; // for mac written earlier

        return apdu_p;
    }

    /**
     * Increment the send sequence counter.
     */
    private void incrementSSC() {
        if (ssc == null || ssc.length <= 0) {
            return;
        }

        for (short s = (short) (ssc.length - 1); s >= 0; s--) {
            if ((short) ((ssc[s] & 0xff) + 1) > 0xff) {
                ssc[s] = 0;
            } else {
                ssc[s]++;
                break;
            }
        }
    }
    
    /***
     * Get the amount of space to reserve in the buffer when using secure 
     * messaging.
     * 
     * @param length length of plain text in which this offset depends.
     * @return the amount of space to reserve.
     */
    private short getApduBufferOffset(short length) {
        short do87Bytes = 2; // 0x87 length data 0x01
        // smallest multiple of 8 strictly larger than plaintextLen + 1
        // byte is probably the length of the cipher text (including do87 0x01)
        short do87DataLen = (short) ((((short) (length + 8) / 8) * 8) + 1);        
        
        if (do87DataLen < 0x80) {
            do87Bytes++;
        } else if (do87DataLen <= 0xff) {
            do87Bytes += 2;
        } else {
            do87Bytes += (short) (length > 0xff ? 2 : 1);
        }
        
        return do87Bytes;
    }
    
    /**
     * Set the SSC
     * 
     * @param buffer byte array containing the SSC
     * @param offset location of the data in the buffer
     */
    public void setSSC(byte[] buffer, short offset) {
    	Util.arrayCopy(buffer, offset, ssc, (short)0, SSC_SIZE);
    	ssc_set[0] = true;
    }
    
    /**
     * @return size in bytes of the SSC
     */    
    public short getSSCSize() {
    	return SSC_SIZE;
    }
    
    /**
     * @return boolean indicating whether SSC has been set
     */    
    public boolean isSetSSC() {
    	return ssc_set[0];
    }    
}
