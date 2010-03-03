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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.joelhockey.codec.Hex;
import com.joelhockey.codec.TLV;
import com.joelhockey.iso24727.ISO24727.ACLListReturn;
import com.joelhockey.iso24727.ISO24727.CardApplicationConnectReturn;
import com.joelhockey.iso24727.ISO24727.CardApplicationListReturn;
import com.joelhockey.iso24727.ISO24727.DIDAuthenticateReturn;
import com.joelhockey.iso24727.ISO24727.DIDGetReturn;
import com.joelhockey.iso24727.ISO24727.DSIReadReturn;
import com.joelhockey.iso24727.ISO24727.DataSetSelectReturn;
import com.joelhockey.smartcard.APDURes;
import com.joelhockey.smartcard.Smartcard;
import com.joelhockey.smartcard.SmartcardException;

public class ISO24727Smartcard {
    private static final int SW_9000_OK = 0x9000;
    private Smartcard card;
    private int cla = 0x00;
    private int ins = 0xc2;
    private boolean secureOn = false;
    private SecureMessaging secure;
    private Map<String, byte[]> cnxnHandles = new HashMap<String, byte[]>();
    private byte[] cnxnHandle;

    public ISO24727Smartcard(Smartcard card) {
        this.card = card;
    }

    public void cardApplicationConnect(String ifdName, byte[] aid) throws SmartcardException, ISO24727Exception, SecureMessagingException {
        byte[] req = ISO24727.cardApplicationConnect(ifdName, aid);
        byte[] res = transmit(req, "CardApplicationConnect");
        CardApplicationConnectReturn isoReturn = new CardApplicationConnectReturn(res);
        cnxnHandles.put(Hex.b2s(aid), isoReturn.getConnectionHandle());
        cnxnHandle = isoReturn.getConnectionHandle();
    }
    
    public List<byte[]> cardApplicationList() throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.cardApplicationList(cnxnHandle);
        byte[] res = transmit(req, "CardApplicationList");
        CardApplicationListReturn isoReturn = new CardApplicationListReturn(res);
        return isoReturn.getCardApplicationNameList();
    }
    
    public TLV didGet(int didScope, String didName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.didGet(cnxnHandle, didScope, didName);
        byte[] res = transmit(req, "DIDGet");
        DIDGetReturn isoReturn = new DIDGetReturn(res);
        return isoReturn.getMarker();
    }

    public TLV didAuthenticate(int didScope, String didName, byte[] didAuthData) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.didAuthenticate(cnxnHandle, didScope, didName, didAuthData);
        byte[] res = transmit(req, "DIDAuthenticate");
        DIDAuthenticateReturn isoReturn = new DIDAuthenticateReturn(res);
        return isoReturn.getAuthProtocolData();
    }
    
    public void dataSetSelect(String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.dataSetSelect(cnxnHandle, dataSetName);
        byte[] res = transmit(req, "DataSetSelect");
        DataSetSelectReturn isoReturn = new DataSetSelectReturn(res);
    }

    public TLV dsiRead(String dsiName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.dsiRead(cnxnHandle, dsiName);
        byte[] res = transmit(req, "DSIRead");
        DSIReadReturn isoReturn = new DSIReadReturn(res);
        return isoReturn.getDsi();
    }

    public TLV aclListApp(byte[] aid) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.aclListApp(cnxnHandle, aid);
        byte[] res = transmit(req, "ACLList");
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }
    
    public TLV aclListDID(String didName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.aclListDID(cnxnHandle, didName);
        byte[] res = transmit(req, "ACLList");
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }
    
    public TLV aclListDataSet(String dataSetName) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        byte[] req = ISO24727.aclListDataSet(cnxnHandle, dataSetName);
        byte[] res = transmit(req, "ACLList");
        ACLListReturn isoReturn = new ACLListReturn(res);
        return isoReturn.getAcl();
    }

    
    private byte[] transmit(byte[] req, String action) throws ISO24727Exception, SmartcardException, SecureMessagingException {
        if (secureOn) req = secure.encryptAndMac(req);
        APDURes res = card.transmit(cla, ins, 0, 0, req, 0);
        if (res.getSW() != SW_9000_OK) {
            throw new ISO24727Exception("Expected SW!=0x9000, apdu: " + Hex.b2s(res.getBytes()), action, res.getSW(), null);
        }
        return secureOn ? secure.decryptAndValidateMac(res.getData()) : res.getData();
    }
}