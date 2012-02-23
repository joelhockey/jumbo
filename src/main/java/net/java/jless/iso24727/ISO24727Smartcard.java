/*
 * Copyright 2010-2012 Joel Hockey (joel.hockey@gmail.com). All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.java.jless.iso24727;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.java.jless.codec.Hex;
import net.java.jless.codec.TLV;
import net.java.jless.iso24727.ISO24727.ACLListReturn;
import net.java.jless.iso24727.ISO24727.CardApplicationConnectReturn;
import net.java.jless.iso24727.ISO24727.CardApplicationListReturn;
import net.java.jless.iso24727.ISO24727.DIDAuthenticateReturn;
import net.java.jless.iso24727.ISO24727.DIDGetReturn;
import net.java.jless.iso24727.ISO24727.DIDListReturn;
import net.java.jless.iso24727.ISO24727.DSIListReturn;
import net.java.jless.iso24727.ISO24727.DSIReadReturn;
import net.java.jless.iso24727.ISO24727.DataSetListReturn;
import net.java.jless.iso24727.ISO24727.DataSetSelectReturn;
import net.java.jless.smartcard.APDURes;
import net.java.jless.smartcard.Smartcard;
import net.java.jless.smartcard.SmartcardException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Wrapper for ISO24727 Smartcard
 */
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
    private String currentAid = "";
    private String currentDataSet = "";

    /**
     * Create ISO24727 Smartcard wrapping provided smartcard
     * @param card underlying smartcard
     */
    public ISO24727Smartcard(Smartcard card) {
        this.card = card;
    }

    private byte[] cnxnHandle() { return cnxnHandles.get(currentAid); }

    // ===== Connection Service =====
    // CardApplicationConnect
    public void cardApplicationConnect(String aid) throws SmartcardException, ISO24727Exception, SecureMessagingException {
        byte[] aidbuf = Hex.s2b(aid);
        if (currentAid.equals(Hex.B2S(aidbuf))) {
            return;
        }
        TLV req = ISO24727.cardApplicationConnect(card.getIFDName(), aidbuf);
        byte[] res = transmit(req, "CardApplicationConnect", aid);
        CardApplicationConnectReturn isoReturn = new CardApplicationConnectReturn(res);
        currentAid = Hex.B2S(aidbuf);
        cnxnHandles.put(currentAid, isoReturn.getConnectionHandle());
    }

    // CardApplicationDisconnect
    // CardApplicationStartSession
    // CardApplicationEndSession

    // ===== Card-Application Service =====
    // CardApplicationList

    public List<byte[]> cardApplicationList() throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(AID_ALPHA);
        TLV req = ISO24727.cardApplicationList(cnxnHandle());
        byte[] res = transmit(req, "CardApplicationList", null);
        CardApplicationListReturn isoReturn = new CardApplicationListReturn(res);
        return isoReturn.getCardApplicationNameList();
    }

    // CardApplicationCreate
    // CardApplicationDelete
    // CardApplicationServiceList
    // CardApplicationServiceCreate
    // CardApplicationServiceLoad
    // CardApplicationServiceDelete
    // CardApplicationServiceDescribe

    // ===== Named Data Service =====
    // DataSetList
    public List<String> dataSetList(String aid) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        TLV req = ISO24727.dataSetList(cnxnHandle());
        byte[] res = transmit(req, "DataSetList", aid);
        DataSetListReturn isoReturn = new DataSetListReturn(res);
        return isoReturn.getDataSetNameList();
    }

    // DataSetCreate
    // DataSetSelect
    public void dataSetSelect(String aid, String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        if (currentDataSet.equals(dataSetName)) {
            return;
        }
        TLV req = ISO24727.dataSetSelect(cnxnHandle(), dataSetName);
        byte[] res = transmit(req, "DataSetSelect", aid + ":" + dataSetName);
        DataSetSelectReturn isoReturn = new DataSetSelectReturn(res);
        currentDataSet = dataSetName;
    }

    // DataSetDelete

    // DSIList
    public List<String> dsiList(String aid, String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        dataSetSelect(aid, dataSetName);
        TLV req = ISO24727.dsiList(cnxnHandle());
        byte[] res = transmit(req, "DSIList", aid);
        DSIListReturn isoReturn = new DSIListReturn(res);
        return isoReturn.getDSINameList();
    }

    // DSICreate
    // DSIDelete
    // DSIRead
    public TLV dsiRead(String aid, String dataSetName, String dsiName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        dataSetSelect(aid, dataSetName);
        TLV req = ISO24727.dsiRead(cnxnHandle(), dsiName);
        byte[] res = transmit(req, "DSIRead", aid + ":" + dataSetName + ":" + dsiName);
        DSIReadReturn isoReturn = new DSIReadReturn(res);
        return isoReturn.getDsi();
    }


    // ===== Cryptographic Service =====
    // Encipher
    // Decipher
    // GetRandom
    // Hash
    // Sign
    // VerifySignature
    // VerifyCertificate

    // ===== Differential-Identity Service =====
    // DIDList
    public List<String> didList(String aid) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        TLV req = ISO24727.didList(cnxnHandle());
        byte[] res = transmit(req, "DIDList", "");
        DIDListReturn isoReturn = new DIDListReturn(res);
        return isoReturn.getDIDNameList();
    }

    // DIDCreate

    // DIDGet
    public TLV didGet(boolean globalScope, String didName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        if (globalScope) {
            cardApplicationConnect(AID_ALPHA);
        }
        int didScope = globalScope ? 1 : 0;
        TLV req = ISO24727.didGet(cnxnHandle(), didScope, didName);
        byte[] res = transmit(req, "DIDGet", didScope + ":" + didName);
        DIDGetReturn isoReturn = new DIDGetReturn(res);
        return isoReturn.getMarker();
    }

    // DIDUpdate
    // DIDDelete

    // DIDAuthenticate
    public TLV didAuthenticate(boolean  globalScope, String didName, byte[] didAuthData) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        int didScope = globalScope ? 1 : 0;
        TLV req = ISO24727.didAuthenticate(cnxnHandle(), didScope, didName, didAuthData);
        String param = null;
        if (log.isDebugEnabled()) {
            param = didScope + ":" + didName + ":" + Hex.b2s(didAuthData);
        }
        byte[] res = transmit(req, "DIDAuthenticate", param);
        DIDAuthenticateReturn isoReturn = new DIDAuthenticateReturn(res);
        return isoReturn.getAuthProtocolData();
    }

    // ===== Authorization Service =====
    // ACLList
    public TLV aclListApp(String aid) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(AID_ALPHA);
        TLV req = ISO24727.aclListApp(cnxnHandle(), Hex.s2b(aid));
        byte[] res = transmit(req, "ACLList", "AID " + aid);
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    public TLV aclListDID(String aid, String didName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        TLV req = ISO24727.aclListDID(cnxnHandle(), didName);
        byte[] res = transmit(req, "ACLList", "DID " + didName);
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    public TLV aclListDataSet(String aid, String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        cardApplicationConnect(aid);
        TLV req = ISO24727.aclListDataSet(cnxnHandle(), dataSetName);
        byte[] res = transmit(req, "ACLList", "DataSet " + aid + ":" + dataSetName);
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    // ACLModify

    private byte[] transmit(TLV req, String action, String params) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        if (log.isInfoEnabled()) {
            if (params != null) {
                action += " " + params;
            }
            log.info("> " + action);
        }
        if (log.isDebugEnabled()) {
            log.debug("\n" + req.dump());
        }
        long start = System.currentTimeMillis();

        byte[] encoded = req.encode();
        if (secureOn) {
            encoded = secure.encryptAndMac(encoded);
        }
        APDURes res = card.transmit(cla, ins, 0, 0, encoded, 0);
        if (res.getSW() != SW_9000_OK) {
            throw new ISO24727Exception("Error expected SW=0x9000, got apdu: " + Hex.b2s(res.getBytes()), action, res.getSW(), null);
        }
        long end = java.lang.System.currentTimeMillis();
        encoded = res.getBytes();
        if (log.isInfoEnabled()) {
            log.info("< " + action + " (" + (end-start) + ") " + Hex.b2s(encoded));
        }
        if (secureOn) {
            encoded = secure.decryptAndValidateMac(encoded);
        }
        return encoded;
    }
}
