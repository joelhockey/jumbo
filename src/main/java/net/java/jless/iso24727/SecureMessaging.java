/*
 * Copyright 2010 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 * THIS SOURCE CODE IS PROVIDED BY JOEL HOCKEY WITH A 30-DAY MONEY BACK
 * GUARANTEE.  IF THIS CODE DOES NOT MEAN WHAT IT SAYS IT MEANS WITHIN THE
 * FIRST 30 DAYS, SIMPLY RETURN THIS CODE IN ORIGINAL CONDITION FOR A PARTIAL
 * REFUND.  IN ADDITION, I WILL REFORMAT THIS CODE USING YOUR PREFERRED
 * BRACE-POSITIONING AND INDENTATION.  THIS WARRANTY IS VOID IF THE CODE IS
 * FOUND TO HAVE BEEN COMPILED.  NO FURTHER WARRANTY IS OFFERED.
 */
package net.java.jless.iso24727;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.java.jless.codec.Buf;
import net.java.jless.codec.Hex;
import net.java.jless.codec.TLV;


/**
 * ISO24727-4 Secure Messaging 
 * @author Joel Hockey
 */
public class SecureMessaging {
    private static final byte[] PAD_0X80 = new byte[] {(byte) 0x80};
    private byte[] encSessionKey;
    private byte[] macSessionKey;
    private byte[] sendSequenceCounter;
    private Cipher aes;

    /**
     * ISO24727-4 Secure Messaging.
     * @param derivInputs Derivation inputs
     */
    public SecureMessaging(byte[]... derivInputs) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException("Unexpected NoSuchAlgorithmException", nsae);
        }
        
        // kdf1 uses key, seed, counter
        // [cardSaticKey] || onCardNonce || offCardNonce || 0x0? || {0,0,0,0}
        byte[] keySeed = Buf.cat(derivInputs);
        
        md.update(keySeed);
        encSessionKey = Buf.substring(md.digest(new byte[] {0, 0, 0, 0, 0}), -16, 16);
        md.update(keySeed);
        macSessionKey = Buf.substring(md.digest(new byte[] {1, 0, 0, 0, 0}), -16, 16);
        md.update(keySeed);
        sendSequenceCounter = Buf.substring(md.digest(new byte[] {2, 0, 0, 0, 0}), -16, 16);

        sendSequenceCounter[14] = 0;
        sendSequenceCounter[15] = 0;
        
        try {
            aes = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Unexpected GeneralSecurityException", gse);
        }
    }

    /**
     * Increment and return send sequence counter
     * @return incremented send sequence counter
     */
    public byte[] incSendSequenceCounter() {
        sendSequenceCounter[15]++;
        if (sendSequenceCounter[15] == 0) {
            sendSequenceCounter[14]++;
        }
        return sendSequenceCounter;
    }

    /**
     * Mac msgs using ISO9797-1 padding type 2
     * @param msgs msgs to mac
     * @return mac
     */
    public byte[] mac(byte[]... msgs) {
        return mac(2, msgs);
    }

    /**
     * Mac msgs using ISO9797-1 padding type (1 or 2)
     * @param padType 1 or 2
     * @param msgs msgs to mac
     * @return mac
     */
    public byte[] mac(int padType, byte[]... msgs) {
        int totalLen = 0;
        try {
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(macSessionKey, "AES"), new IvParameterSpec(new byte[16]));
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Unexpected GeneralSecurityException", gse);
        }
        byte[] encrypted = null;
        for (byte[] msg : msgs) {
            if (msg == null) {
                continue;
            }
            encrypted = aes.update(msg);
            totalLen += msg.length;
        }

        // no padding if type 1, and already block aligned
        if (padType == 1 && (totalLen & 0x0f) == 0) {
            return Buf.substring(encrypted, -16, 16);
        }
        
        // there is some padding
        byte[] pad = new byte[16 - (totalLen & 0x0f)];
        if (padType == 2) {
            pad[0] = (byte) 0x80; // type 2 padding has 0x80 (single 1-bit) first
        }

        try {
            return Buf.substring(aes.doFinal(pad), -16, 16);
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Unexpected GeneralSecurityException", gse);
        }
    }
        
    
    /**
     * As per ISO24727-4 A.1 Secure Messaging
     * <ol>
     * <li> The original command APDU CmdAPDU.1 is encapsulated in a DO with tag Tcmd.  This DO is
     * encapsulated in an ENVELOPE command.
     * <li> The command header is transformed as shown in A.1.1.2 and the command data field is
     * encapsulated in a DO with tag Tcg as shown in A.1.1.3 and the Le field is encapsulated in a DO with
     * tag Tle as shown in A.1.1.5
     * <li> The transformed command header is padded as shown in A.1.1.1.  The result is concatenated with
     * DOcg and DOle.
     * <li> The result from step (3) is the input for MAC calculation.
     * <li> The secured command APDU has the following elements:
     *   <ol>
     *   <li> Transformed command header CH'.
     *   <li> The data field of the secured command APDU contains DOcg, DOle and DOcc.
     *   <li> An OLe field named 'New Le'.
     *   </ol>
     * </ol>
     * @param msg plaintext msg
     * @return encrypted(msg || mac)
     */
    public byte[] encryptAndMac(byte[] msg) {
          
        // (1) put into TLV using tag 0x52 (Tcmd)
        byte[] tag52 = TLV.encode(0x40, 0x12,
            // apdu header (extended length) - using ENVELOPE (0xc2)
            new byte[] {0, (byte) 0xc2, 0, 0, 0, (byte) (msg.length >> 8), (byte) msg.length},
            msg, // msg
            new byte[2] //le (extended)
        );
        
        // (2) A.1.1.3 - encrypt value from (1), then wrap in tag 0x85 (Tcg)
        // pad using ISO9797 part 2 (single 1 bit, then all zeros)
        int padLen = 16 - (tag52.length & 0x0f);
        byte[] encryptInput = Buf.cat(tag52, Buf.substring(PAD_0X80, 0, padLen)); 
        
        byte[] ssc = incSendSequenceCounter();
        byte[] encrypted;
        try {
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encSessionKey, "AES"), new IvParameterSpec(ssc));
            encrypted = aes.doFinal(encryptInput);
        } catch (GeneralSecurityException  gse) {
            throw new RuntimeException("Unexpected GeneralSecurityException", gse);
        }
        byte[] tag85 = TLV.encode(0x80, 0x05, encrypted);
        
        // (3,4) mac => SSC || CH' (padded) || DOcg (tag85) || DOle (tag97)
        byte[] tag97 = Hex.s2b("97020000"); // extended Le inside tag 0x97
        byte[] tag8e = TLV.encode(0x80, 0x0e, mac(
          ssc, // send sequence counter
          Hex.s2b("0CC30000800000000000000000000000"), // Enveloped Command header padded
          tag85, // encrypted data
          tag97 // Le
        ));
        
        // (5) result is CH' || Lc || DOcg (tag85) || DOle (tag97) || DOcc (tag8e) || New Le
        // We will leave off APDU header and Le which leaves DOcg || DOle || DOcc
        return Buf.cat(tag85, tag97, tag8e);
    }

    /**
     * As per ISO24727-4 A.1 Secure Messaging
     * <ol>
     * <li> The original response APDU RspAPDU.1 is encapsulated in a DO with tag Trsp.  This DO is taken as
     * the response data field of a response APDU.
     * <li> The data of this response APDU is enciphered and encapsulated in a DO with tag Tcg as shon in
     * A.1.1.3 and the status bytes are encapsulated in a DO with tag Tsw as shown in A.1.1.6.
     * <li> DOcg and DOsw are concatenated and then padded as shown in A.1.1.1.
     * <li> The result from step (3) is the input for MAC calculation.
     * <li> The secured response APDU contains the following elements
     *   <ol>
     *   <li> The data field is the concatenation of DOcg, DOsw and DOcc.
     *   <li> The trailer contains the status bytes "SW1-SW2".
     *   </ol>
     * </ol>
     * @param msg message to decrypt and validate mac
     * @return plaintext msg
     * @throws SecureMessagingException if error decrypting of validating mac
     */
    public byte[] decryptAndValidateMac(byte[] msg) throws SecureMessagingException {
        
        // (1,2) decrypt
        List<TLV> parts = TLV.split(msg);
        byte[] tags = new byte[parts.size()];
        for (int i = 0; i < parts.size(); i++) {
            tags[i] = (byte) (parts.get(i).getcc() | parts.get(i).gett());
        }
        String expectedTags = "85998e";
        String actualTags = Hex.b2s(tags);
        if (!expectedTags.equals(actualTags)) {
            throw new SecureMessagingException(String.format("Could not parse encrypted response.  Expected 3 TLVs with tags (0x85, 0x99, 0x8e), got: %d TLVs with tags (%s): %s",
                    parts.size(), actualTags, Hex.b2s(msg)));
        }

        byte[] ssc = incSendSequenceCounter();
        byte[] decrypted;
        try {
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encSessionKey, "AES"), new IvParameterSpec(ssc));
            decrypted = aes.doFinal(parts.get(0).getv());
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Unexpected GeneralSecurityException", gse);
        }
        TLV tlv = new TLV(decrypted);
        if (0x53 != (tlv.getcc() | tlv.gett())) {
            throw new SecureMessagingException(String.format(
                    "Expected DOcg with tag 0x53, got tag 0x%02x", (tlv.getcc() | tlv.gett())));
        }
        // (3,4) validate mac
        byte[] expectedcc = mac(ssc, parts.get(0).encode(), parts.get(1).encode());
        if (!Arrays.equals(expectedcc, parts.get(2).getv())) {
            throw new SecureMessagingException(String.format(
                    "Invalid MAC, expected %s, got %s", Hex.b2s(expectedcc), Hex.b2s(parts.get(2).getv())));
        }
        
        return tlv.getv();
    }
}