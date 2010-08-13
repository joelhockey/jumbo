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
package com.joelhockey.iso24727;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.joelhockey.codec.Buf;
import com.joelhockey.codec.Hex;
import com.joelhockey.codec.TLV;
import com.joelhockey.iso24727.ISO24727.ACLListReturn;
import com.joelhockey.iso24727.ISO24727.CardApplicationConnectReturn;
import com.joelhockey.iso24727.ISO24727.CardApplicationListReturn;
import com.joelhockey.iso24727.ISO24727.CardApplicationStartSessionReturn;
import com.joelhockey.iso24727.ISO24727.DIDAuthenticateReturn;
import com.joelhockey.iso24727.ISO24727.DIDGetReturn;
import com.joelhockey.iso24727.ISO24727.DSIReadReturn;
import com.joelhockey.iso24727.ISO24727.DataSetSelectReturn;
import com.joelhockey.jless.pkix.Cert;
import com.joelhockey.jless.pkix.CertPath;
import com.joelhockey.jless.pkix.CertPathException;
import com.joelhockey.jless.security.Digest;
import com.joelhockey.smartcard.APDURes;
import com.joelhockey.smartcard.Smartcard;
import com.joelhockey.smartcard.SmartcardException;

public class ISO24727Smartcard {
    private static final Log log = LogFactory.getLog(ISO24727Smartcard.class);
    public static final String AID_ALPHA = ISO24727.AID_ALPHA;
    public static final int SW_9000_OK = 0x9000;
    private Smartcard card;
    private int cla = 0x00;
    private int ins = 0xc2;
    private boolean secureOn = false;
    private SecureMessaging secure;
    private Map<String, byte[]> cnxnHandles = new HashMap<String, byte[]>();
    private String currentAid;
    private String currentDataSet = "";

    public ISO24727Smartcard(Smartcard card) {
        this.card = card;
    }

    private byte[] cnxnHandle() { return cnxnHandles.get(currentAid); }

    public void cardApplicationConnect(String aid) throws SmartcardException, ISO24727Exception, SecureMessagingException {
        byte[] aidbuf = Hex.s2b(aid);
        if (currentAid.equals(Hex.B2S(aidbuf))) {
            return;
        }
        byte[] req = ISO24727.cardApplicationConnect(card.getIFDName(), aidbuf);
        byte[] res = transmit(req, "CardApplicationConnect", aid);
        CardApplicationConnectReturn isoReturn = new CardApplicationConnectReturn(res);
        currentAid = Hex.B2S(aidbuf);
        cnxnHandles.put(currentAid, isoReturn.getConnectionHandle());
    }

    public List<byte[]> cardApplicationList() throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(AID_ALPHA);
        byte[] req = ISO24727.cardApplicationList(cnxnHandle());
        byte[] res = transmit(req, "CardApplicationList", null);
        CardApplicationListReturn isoReturn = new CardApplicationListReturn(res);
        return isoReturn.getCardApplicationNameList();
    }

    public TLV didGet(int didScope, String didName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(AID_ALPHA);
        byte[] req = ISO24727.didGet(cnxnHandle(), didScope, didName);
        byte[] res = transmit(req, "DIDGet", didScope + ":" + didName);
        DIDGetReturn isoReturn = new DIDGetReturn(res);
        return isoReturn.getMarker();
    }

    public TLV didAuthenticate(int didScope, String didName, byte[] didAuthData) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.didAuthenticate(cnxnHandle(), didScope, didName, didAuthData);
        String param = null;
        if (log.isDebugEnabled()) {
            param = didScope + ":" + didName + ":" + Hex.b2s(didAuthData);
        }
        byte[] res = transmit(req, "DIDAuthenticate", param);
        DIDAuthenticateReturn isoReturn = new DIDAuthenticateReturn(res);
        return isoReturn.getAuthProtocolData();
    }

    public void dataSetSelect(String aid, String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        if (currentDataSet.equals(dataSetName)) {
            return;
        }
        byte[] req = ISO24727.dataSetSelect(cnxnHandle(), dataSetName);
        byte[] res = transmit(req, "DataSetSelect", aid + ":" + dataSetName);
        DataSetSelectReturn isoReturn = new DataSetSelectReturn(res);
        currentDataSet = dataSetName;
    }

    public TLV dsiRead(String aid, String dataSetName, String dsiName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        dataSetSelect(aid, dataSetName);
        byte[] req = ISO24727.dsiRead(cnxnHandle(), dsiName);
        byte[] res = transmit(req, "DSIRead", aid + ":" + dataSetName + ":" + dsiName);
        DSIReadReturn isoReturn = new DSIReadReturn(res);
        return isoReturn.getDsi();
    }

    public TLV aclListApp(String aid) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(AID_ALPHA);
        byte[] req = ISO24727.aclListApp(cnxnHandle(), Hex.s2b(aid));
        byte[] res = transmit(req, "ACLList", "AID " + aid);
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    public TLV aclListDID(String aid, String didName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        byte[] req = ISO24727.aclListDID(cnxnHandle(), didName);
        byte[] res = transmit(req, "ACLList", "DID " + didName);
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    public TLV aclListDataSet(String aid, String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        byte[] req = ISO24727.aclListDataSet(cnxnHandle(), dataSetName);
        byte[] res = transmit(req, "ACLList", "DataSet " + aid + ":" + dataSetName);
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    public void secureSessionAsymmetric(List<X509Certificate> trustedCerts, List<X509Certificate> intermediateCerts,
            boolean checkRevocation) throws ISO24727Exception, SmartcardException, SecureMessagingException, GeneralSecurityException, CertPathException {

        if (secureOn) {
            throw new ISO24727Exception("Secure Session already exists for " + card, "CardApplicationStartSession", 0, null);
        }

        cardApplicationConnect(AID_ALPHA);

        // CasskeAuth1Req ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   certificateChain [1] BOOLEAN
        // }
        boolean certificateChain = trustedCerts != null && trustedCerts.size() > 0;
        byte[] casskeAuth1Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {1}), // step 1
            new TLV(0x80, 1, new byte[] {certificateChain ? (byte) 0xff : 0}) // set to TRUE if any trustedCerts included
        );

        byte[] req = ISO24727.cardApplicationStartSession(cnxnHandle(), 1, "24", casskeAuth1Req);
        byte[] res = transmit(req, "CardApplicationStartSession", "CASSKE 1");
        CardApplicationStartSessionReturn iso24727Return = new CardApplicationStartSessionReturn(res, ISO24727.RETURN_CODE_API_NEXT_REQUEST);
        TLV casskeAuth1Resp = iso24727Return.getAuthProtocolData();

        // CasskeAuth1Resp ::= SEQUENCE {
        //   authStep                   [0] INTEGER
        //   keySize                    [1] INTEGER,
        //   onCardNonce                [2] OCTET STRING,
        //   transportKeyIdentifier     [3] OCTET STRING,
        //   transportPublicKeyMaterial [4] SEQUENCE OF Certificate
        // }
        byte[] onCardNonce = casskeAuth1Resp.get(2).getv();
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (TLV c : casskeAuth1Resp.get(4).split()) {
            certs.add(Cert.x509(c.encode()));
        }
        X509Certificate cardCert = certs.get(0);

        // validate certpath
        if (intermediateCerts != null) {
            certs.addAll(intermediateCerts);
        }
        CertPath.certPath(cardCert, certs, trustedCerts, checkRevocation);

        // CasskeAuth2Req ::= SEQUENCE {
        //   authStep       [0] INTEGER,
        //   encryptedNonce [1] OCTET STRING,
        //   macedNonce     [2] OCTET STRING OPTIONAL
        // }

        // generate random nonce, encrypt and mac
        byte[] offCardNonce = Buf.random(onCardNonce.length);
        Cipher rsaOaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsaOaep.init(javax.crypto.Cipher.ENCRYPT_MODE, cardCert.getPublicKey());
        byte[] encryptedNonce = rsaOaep.doFinal(offCardNonce);

        secure = new SecureMessaging(onCardNonce, offCardNonce);

        byte[] macedNonce = secure.mac(1, offCardNonce);
        byte[] casskeAuth2Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {2}), // authStep [0] INTEGER (2)
            new TLV(0x80, 1, encryptedNonce), // encryptedNonce [1] OCTET STRING
            new TLV(0x80, 2, macedNonce) // macedNonce [2] OCTET STRING
        );

        req = ISO24727.cardApplicationStartSession(cnxnHandle(), 1, "24", casskeAuth2Req);
        res = transmit(req, "CardApplicationStartSession", "CASSKE 2");
        iso24727Return = new CardApplicationStartSessionReturn(res);
        TLV casskeAuth2Resp = iso24727Return.getAuthProtocolData();

        // CasskeAuth2Resp ::= SEQUENCE {
        //   authStep      [0] INTEGER
        //   macReturnCode [1] OCTET STRING
        // }

        byte[] expectedReturnCodeMac = secure.mac(1, iso24727Return.getReturnCode().getBytes());
        if (!Arrays.equals(expectedReturnCodeMac, casskeAuth2Resp.get(1).getv())) {
            throw new SecureMessagingException("Invalid ReturnCode MAC, expected " + Hex.b2s(expectedReturnCodeMac) + ", got " + Hex.b2s(casskeAuth2Resp.get(1).getv()));
        }
        secureOn = true;
    }

    public void secureSessionSymmetric(byte[] masterKey, byte[] cardStaticKey) throws GeneralSecurityException, ISO24727Exception, SmartcardException, SecureMessagingException {
        if (secureOn) {
            throw new ISO24727Exception("Secure Session already exists for " + card, "CardApplicationStartSession", 0, null);
        }

        cardApplicationConnect(AID_ALPHA);

        // CasmaskeAuth1Req ::= SEQUENCE {
        //   authStep     [0] INTEGER,
        //   offCardNonce [1] OCTET STRING (16)
        // }

        byte[] offCardNonce = Buf.random(16);
        byte[] casmaskeAuth1Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {1}),
            new TLV(0x80, 1, offCardNonce)
        );

        byte[] req = ISO24727.cardApplicationStartSession(cnxnHandle(), 1, "32", casmaskeAuth1Req);
        byte[] res = transmit(req, "CardApplicationStartSession", "CASMASKE 1");
        CardApplicationStartSessionReturn iso24727Return = new CardApplicationStartSessionReturn(res, ISO24727.RETURN_CODE_API_NEXT_REQUEST);
        TLV casmaskeAuth1Resp = iso24727Return.getAuthProtocolData();

        // CasmaskeAuth1Resp ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   onCardNonce      [1] OCTET STRING (16),
        //   onCardCryptogram [2] OCTET STRING,
        //   keyIdentifier    [3] OCTET STRING
        // }

        byte[] onCardNonce = casmaskeAuth1Resp.get(1).getv();

        // KeyIdentifier ::= SEQUENCE {
        //   masterKeylabel [0] OCTET STRING,
        //   iv             [1] OCTET STRING,
        //   iin            [2] OCTET STRING,
        //   cin            [3] OCTET STRING
        // }

        byte[] iv = casmaskeAuth1Resp.get(3).get(0).get(1).getv();
        byte[] iin = casmaskeAuth1Resp.get(3).get(0).get(2).getv();
        byte[] cin = casmaskeAuth1Resp.get(3).get(0).get(3).getv();
        log.debug("iv: " + Hex.b2s(iv));
        log.debug("iin: " + Hex.b2s(iin));
        log.debug("cin: " + Hex.b2s(cin));

        Cipher des3 = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        des3.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey, "DESede"), new IvParameterSpec(iv));
        byte[] data = Buf.cat(Buf.substring(cin, -8, 8), Buf.substring(iin, -8, 8));

        byte[] derivedCardStaticKey = Buf.substring(des3.doFinal(data), 0, 16);
        log.debug("derived casmaske card static key:" + Hex.b2s(derivedCardStaticKey));
        if (cardStaticKey == null) {
            cardStaticKey = derivedCardStaticKey;
        } else {
            log.debug("using provided card static key  :" + Hex.b2s(cardStaticKey));
        }

        secure = new SecureMessaging(cardStaticKey, onCardNonce, offCardNonce);

        // onCardCryptogram verify
        byte[] onCardCryptogramVerify = secure.mac(secure.incSendSequenceCounter(), onCardNonce, offCardNonce);
        if (!Arrays.equals(onCardCryptogramVerify, casmaskeAuth1Resp.get(2).getv())) {
            throw new SecureMessagingException("Invalid OnCardCryptogram, expected " + Hex.b2s(onCardCryptogramVerify) + ", got " + Hex.b2s(casmaskeAuth1Resp.get(2).getv()));
        }

        byte[] offCardCryptogram = secure.mac(secure.incSendSequenceCounter(), offCardNonce, onCardNonce);

        // CasmaskeAuth2Req ::= SEQUENCE {
        //   authStep            [0] INTEGER,
        //   offCardCryptogram   [1] OCTET STRING (16),
        //   encSessionKey       [2] OCTET STRING OPTIONAL,
        //   macSessionKey       [3] OCTET STRING OPTIONAL,
        //   sendSequenceCounter [4] OCTET STRING OPTIONAL
        // }

        byte[] casmaskeAuth2Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {2}),
            new TLV(0x80, 1, offCardCryptogram)
        );

        req = ISO24727.cardApplicationStartSession(cnxnHandle(), 1, "32", casmaskeAuth2Req);
        res = transmit(req, "CardApplicationStartSession", "CASMASKE 2");
        iso24727Return = new CardApplicationStartSessionReturn(res);

        secureOn = true;
    }

    public void externalAuthenticate(String didName, PrivateKey privKey, List<X509Certificate> certChain) throws ISO24727Exception, SmartcardException, SecureMessagingException, GeneralSecurityException {
        cardApplicationConnect(AID_ALPHA);

        byte[] eaAuth1Req = TLV.encode(0x20, 0x10, new TLV(0x80, 0, new byte[] {1})); // step 1
        byte[] req = ISO24727.didAuthenticate(cnxnHandle(), 1, didName, eaAuth1Req);
        byte[] res = transmit(req, "DIDAuthenticate", "External 1");
        DIDAuthenticateReturn iso24727Return = new DIDAuthenticateReturn(res, ISO24727.RETURN_CODE_API_NEXT_REQUEST);
        TLV eaAuth1Resp = iso24727Return.getAuthProtocolData();

        // EaAuth1Resp ::= SEQUENCE {
        //   authStep              [0] INTEGER,
        //   challenge             [1] OCTET STRING,
        //   trustAnchorIdSequence [2] SEQUENCE OF TrustAnchorId,
        //   useProfile            [3] BOOLEAN
        // }

        // trustAnchorIdSequence contains a list of SubjectKeyIdentifiers
        Set<String> extTrustAnchors = new HashSet<String>();
        for (TLV tlv : eaAuth1Resp.get(2).split()) {
            extTrustAnchors.add(Hex.b2s(tlv.getv()));
        }
        // search the certChain for a cert issued by one of the trust anchors.
        List<byte[]> certsToSend = new ArrayList<byte[]>();
        String trustAnchorId = null;
        for (X509Certificate cert : certChain) {
            String skid = Cert.getSkid(cert);
            if (extTrustAnchors.contains(skid)) {
               trustAnchorId = skid;
               break;
            }
            certsToSend.add(cert.getEncoded());
            String akid = Cert.getAkid(cert);
            if (extTrustAnchors.contains(akid)) {
                trustAnchorId = akid;
                break;
            }
        }

        if (trustAnchorId == null) {
            List<String> skidAkids = new ArrayList<String>();
            for (X509Certificate cert : certChain) {
                skidAkids.add(Cert.getSkid(cert) + "/" + Cert.getAkid(cert));
            }
            throw new ISO24727Exception("Could not authenticate to smartcard trust anchors (" + extTrustAnchors
                    + ") using cert chain (" + skidAkids + ")\n\n" + certChain, "DIDAuthenticate", 0, null);
        }

        Signature sha256WithRsa = Signature.getInstance("SHA256withRSA");
        sha256WithRsa.initSign(privKey);
        sha256WithRsa.update(eaAuth1Resp.get(1).getv());
        byte[] signedChallenge = sha256WithRsa.sign();

        // EaAuth2Req ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   signedChallenge  [1] OCTET STRING OPTIONAL,
        //   certificate      [2] Certificate OPTIONAL,
        //   trustAnchorID    [3] OCTET STRING OPTIONAL
        // }
        int numReqs = Math.max(1, certsToSend.size());
        for (byte[] cert : certsToSend) {
            cert[0] = (byte) 0xa2; // set each cert tag to "[2] IMPLICIT"
        }

        for (int i = 0; i < numReqs; i++) {
            byte[] eaAuth2Req = TLV.encode(0x20, 0x10,
              new TLV(0x80, 0, new byte[] {2}), // step 2
              i == 0 ? new TLV(0x80, 1, signedChallenge) : null, // signedChallenge
              certsToSend.size() > i ? new TLV(certsToSend.get(i)) : null, // certificate if required
              i == numReqs - 1 ? new TLV(0x80, 3, Hex.s2b(trustAnchorId)) : null // trustAnchorId (only send in last msg)
            );

            log.debug("sending eaAuth2Req\n" + Hex.b2s(eaAuth2Req));

            String expectedReturnCode = i == numReqs - 1 ? ISO24727.RETURN_CODE_API_OK : ISO24727.RETURN_CODE_API_NEXT_REQUEST;
            req = ISO24727.didAuthenticate(cnxnHandle(), 1, didName, eaAuth2Req);
            res = transmit(req, "DIDAuthenticate", "External 2." + (i+1) + "/" + numReqs);
            iso24727Return = new DIDAuthenticateReturn(res, expectedReturnCode);
        }
    }

    public void pin(String pin) throws ISO24727Exception, SmartcardException, SecureMessagingException, CertificateException {
        cardApplicationConnect(AID_ALPHA);
        // SpinAuth1Req ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   certificateChain [1] BOOLEAN
        // }
        //
        // SpinAuth1Resp ::= SEQUENCE {
        //   authStep                   [0] INTEGER,
        //   nonce                      [1] OCTET STRING (16),
        //   transportKeyIdentifier     [2] OCTET STRING,
        //   transportPublicKeyMaterial [3] SEQUENCE OF Certificate
        // }
        byte[] spinAuth1Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {1}), // step 1
            new TLV(0x80, 1, new byte[] {0x00}) // certificateChain = FALSE
        );
        byte[] req = ISO24727.didAuthenticate(cnxnHandle(), 1, "1F", spinAuth1Req);
        byte[] res = transmit(req, "DIDAuthenticate", "PIN 1");
        DIDAuthenticateReturn iso24727Return = new DIDAuthenticateReturn(res, ISO24727.RETURN_CODE_API_NEXT_REQUEST);
        TLV spinAuth1Resp = iso24727Return.getAuthProtocolData();
        X509Certificate cardCert = Cert.x509(spinAuth1Resp.get(3).get(0).encode());
        RSAPublicKey pubKey = (RSAPublicKey) cardCert.getPublicKey();

        // SpinAuth2Req ::= SEQUENCE {
        //   authStep     [0] INTEGER
        //   encryptedPIN [1] OCTET STRING
        // }
        //
        // SpinAuth2Resp ::= SEQUENCE {
                //   authStep [0] INTEGER
                // }

        byte[] pad = Buf.random((pubKey.getModulus().bitLength() / 8) - 9 - spinAuth1Resp.get(1).getl());
        byte[] pinBlock9 = Hex.s2b("7f2" + Integer.toHexString(pin.length()) + pin + "ffffffffffffff".substring(pin.length()));
        byte[] pinBlockPadded = Buf.cat(pinBlock9, spinAuth1Resp.get(1).getv(), pad);
        byte[] encryptedPin = new BigInteger(pinBlockPadded).modPow(pubKey.getPublicExponent(), pubKey.getModulus()).toByteArray();
        byte[] spinAuth2Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {2}), // step 2
            new TLV(0x80, 1, encryptedPin)
        );

        req = ISO24727.didAuthenticate(cnxnHandle(), 1, "1F", spinAuth2Req);
        res = transmit(req, "DIDAuthenticate", "PIN 2");
        iso24727Return = new DIDAuthenticateReturn(res);
    }

    public void sharedSecret(String didName, Map<String, String> qAndAMap) throws ISO24727Exception, SmartcardException, SecureMessagingException, IOException, GeneralSecurityException {
        cardApplicationConnect(AID_ALPHA);
        // CassAuth1Req ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   certificateChain [1] BOOLEAN
        // }
        byte[] cassAuth1Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {1}), // step 1
            new TLV(0x80, 1, new byte[] {0x00}) // certificateChain = FALSE
        );

        byte[] req = ISO24727.didAuthenticate(cnxnHandle(), 1, didName, cassAuth1Req);
        byte[] res = transmit(req, "DIDAuthenticate", "SharedSecret " + didName + " 1");
        DIDAuthenticateReturn iso24727Return = new DIDAuthenticateReturn(res, ISO24727.RETURN_CODE_API_NEXT_REQUEST);
        TLV cassAuth1Resp = iso24727Return.getAuthProtocolData();

        // CassAuth1Resp ::= SEQUENCE {
        //   authStep                   [0] INTEGER,
        //   nonce                      [1] OCTET STRING (16),
        //   answerSize                 [2] INTEGER,
        //   indexedQSequence           [3] IndexedQSequence,
        //   transportKeyIdentifier     [4] OCTET STRING,
        //   transportPublicKeyMaterial [5] SEQUENCE OF Certificate
        // }
        //
        // IndexedQSequence :: = SEQUENCE OF IndexedQ
        //
        // IndexedQ::= SEQUENCE {
        //   qNumber [0] INTEGER,
        //   q       [1] OCTET STRING
        // }
        //
        // CassAuth2Req ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   indexedASequence [1] IndexedASequence
        // }
        //
        // IndexedASequence ::= SEQUENCE OF IndexedA
        //
        // IndexedA ::= SEQUENCE {
        //   aNumber    [0] INTEGER,
        //   encryptedA [1] EnvelopedSecretData
        // }
        //
        // AnswerPackage ::= SEQUENCE {
        //   answer [0] OCTET STRING
        //   nonce  [1] OCTET STRING (16),
        // }
        //
        // EnvelopedSecretData ::= SEQUENCE {
        //   encryptedKey     [0] OCTET STRING,
        //   iv               [1] OCTET STRING,
        //   encryptedContent [2] OCTET STRING,
        // }

        List<TLV> indexedAs = new ArrayList<TLV>();
        X509Certificate cardCert = Cert.x509(cassAuth1Resp.get(5).get(0).encode());
        Cipher des3 = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher rsaPkcs15 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        for (TLV indexedQ : cassAuth1Resp.get(3).split()) {
            String question = new String(indexedQ.get(1).getv());

            // check if in qAndAMap
            String answer = qAndAMap.get(question);
            if (answer != null) {
                log.debug(question + " > " + answer);
            } else {
                System.out.print(question + " > ");
                answer = new BufferedReader(new InputStreamReader(System.in)).readLine().trim().toUpperCase();
            }
            // increase answer up to answerSize
            byte[] answerPadded = Buf.substring(answer.getBytes(), 0, new BigInteger(1, cassAuth1Resp.get(2).getv()).intValue());

            // encrypt answer using enveloping des3 and rsa
            byte[] iv = Buf.random(8);
            byte[] deskey = Buf.random(24);
            setOddParity(deskey);
            des3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deskey, "DESede"), new IvParameterSpec(iv));
            byte[] answerPackage = TLV.encode(0x20, 0x10, // AnswerPackage
                new TLV(0x80, 0, answerPadded), // answer [0] OCTET STRING
                new TLV(0x80, 1, cassAuth1Resp.get(1).getv()) // nonce [1] OCTET STRING (16),
            );
            byte[] encContent = des3.doFinal(answerPackage);
            rsaPkcs15.init(Cipher.ENCRYPT_MODE, cardCert.getPublicKey());
            byte[] encKey = rsaPkcs15.doFinal(deskey);
            indexedAs.add(new TLV(0x20, 0x10,
                indexedQ.get(0), // aNumber
                new TLV(0xa0, 1, // EnvelopedSecretData
                    new TLV(0x80, 0, encKey),
                    new TLV(0x80, 1, iv),
                    new TLV(0x80, 2, encContent)
                )
            ));
        }

        byte[] cassAuth2Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {2}), // authStep [0] INTEGER (2)
            new TLV(0xa0, 1, indexedAs) //IndexedASequence
        );

        req = ISO24727.didAuthenticate(cnxnHandle(), 1, didName, cassAuth2Req);
        res = transmit(req, "DIDAuthenticate", "SharedSecret " + didName + " 2");
        iso24727Return = new DIDAuthenticateReturn(res);
    }

    public void internalAuthenticate(String didName, List<X509Certificate> trustedCerts,
            List<X509Certificate> intermediateCerts, boolean checkRevocation) throws ISO24727Exception, SmartcardException, SecureMessagingException, CertificateException, CertPathException, GeneralSecurityException {

        cardApplicationConnect(AID_ALPHA);

        // IaAuth1Req ::= SEQUENCE {
        //   authStep         [0] INTEGER,
        //   certificateChain [1] BOOLEAN
        // }

        byte[] iaAuth1Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {1}), // step 1
            new TLV(0x80, 1, new byte[] {(byte) 0xff}) // certificateChain = TRUE
        );
        byte[] req = ISO24727.didAuthenticate(cnxnHandle(), 1, didName, iaAuth1Req);
        byte[] res = transmit(req, "DIDAuthenticate", "Internal 1");
        DIDAuthenticateReturn iso24727Return = new DIDAuthenticateReturn(res, ISO24727.RETURN_CODE_API_NEXT_REQUEST);
        TLV iaAuth1Resp = iso24727Return.getAuthProtocolData();

        // IaAuth1Resp ::= SEQUENCE {
        //   authStep          [0] INTEGER,
        //   keyIdentifier     [1] OCTET STRING,
        //   publicKeyMaterial [2] SEQUENCE OF Certificate
        // }

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (TLV c : iaAuth1Resp.get(2).split()) {
            certs.add(Cert.x509(c.encode()));
        }
        X509Certificate individualCert = certs.get(0);

        // validate certpath
        if (intermediateCerts != null) {
            certs.addAll(intermediateCerts);
        }
        CertPath.certPath(individualCert, certs , trustedCerts, checkRevocation);

        // IaAuth2Req ::= SEQUENCE {
        //   authStep [0] INTEGER
        //   nonce    [1] OCTET STRING (16)
        // }

        byte[] nonce = Buf.random(16);
        byte[] iaAuth2Req = TLV.encode(0x20, 0x10,
            new TLV(0x80, 0, new byte[] {2}), // authStep [0] INTEGER (2)
            new TLV(0x80, 1, nonce) // nonce
        );

        req = ISO24727.didAuthenticate(cnxnHandle(), 1, didName, iaAuth2Req);
        res = transmit(req, "DIDAuthenticate", "Internal 2");
        iso24727Return = new DIDAuthenticateReturn(res);
        TLV iaAuth2Resp = iso24727Return.getAuthProtocolData();

        // IaAuth2Resp ::= SEQUENCE {
        //   authStep  [0] INTEGER
        //   signature [1] OCTET STRING
        // }
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initVerify(individualCert);
        MessageDigest sha256 = Digest.newSha256();
        byte[] hashedNonce = sha256.digest(nonce);
        sig.update(hashedNonce);
        if (!sig.verify(iaAuth2Resp.get(1).getv())) {
            throw new ISO24727Exception("Internal auth FAILED, invalid signature", "DIDAuthenticate", 0, null);
        }
        log.debug("Internal auth OK, signature verified");
    }

    public boolean bornBefore(String yyyymmdd) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        if (!yyyymmdd.matches("\\d{8}")) {
            throw new ISO24727Exception("invalid date for beforeDate, expect yyyymmdd, got: " + yyyymmdd,
                    "DIDAuthenticate", 0, null);
        }
        cardApplicationConnect("A00000041000010001");
        // AaAuthReq ::= SEQUENCE {
        //   bornBefore [0] VisibleString
        // }
        byte[] aaAuthReq = TLV.encode(0x20, 0x10, new TLV(0x80, 0, yyyymmdd.getBytes()));
        byte[] req = ISO24727.didAuthenticate(cnxnHandle(), 0, "23", aaAuthReq);
        byte[] res = transmit(req, "DIDAuthenticate", "AgeAttain");
        try {
            DIDAuthenticateReturn iso24727Return = new DIDAuthenticateReturn(res);
            return true;
        } catch (ISO24727Exception e) {
            if ("API_INCORRECT_PARAMETER".equals(e.getReturnCode())) {
                throw e;
            }
            return false;
        }
    }

    private void setOddParity(byte[] buf) {
        for (int i = 0; i < buf.length; i++) {
            int b = buf[i] & 0xff;
            b ^= b >> 4;
            b ^= b >> 2;
            b ^= b >> 1;
            buf[i] ^= (b & 1) ^ 0x01;
        }
    }

    private byte[] transmit(byte[] req, String action, String params) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        if (params != null) {
            action += " " + params;
        }
        if (secureOn) req = secure.encryptAndMac(req);
        APDURes res = card.transmit(cla, ins, 0, 0, req, 0);
        if (res.getSW() != SW_9000_OK) {
            throw new ISO24727Exception("Expected SW!=0x9000, apdu: " + Hex.b2s(res.getBytes()), action, res.getSW(), null);
        }
        return secureOn ? secure.decryptAndValidateMac(res.getData()) : res.getBytes();
    }
}
