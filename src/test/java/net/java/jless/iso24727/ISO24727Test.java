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

import java.util.List;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals.State;
import javax.smartcardio.TerminalFactory;

import net.java.jless.codec.Buf;
import net.java.jless.codec.Hex;
import net.java.jless.codec.TLV;
import net.java.jless.iso24727.ISO24727.CardApplicationListReturn;
import net.java.jless.iso24727.ISO24727.DIDListReturn;
import net.java.jless.iso24727.ISO24727.DSIListReturn;
import net.java.jless.iso24727.ISO24727.DataSetListReturn;
import net.java.jless.smartcard.SCIOSmartcard;

import junit.framework.TestCase;

/**
 * Test for ISO24727
 */
public class ISO24727Test extends TestCase {

    // ===== Connection Service =====
    // CardApplicationConnect
    // CardApplicationDisconnect
    // CardApplicationStartSession
    // CardApplicationEndSession

    // ===== Card-Application Service =====
    // CardApplicationList
    public void testCardApplicationList() throws Exception {
        TLV req = ISO24727.cardApplicationList(new byte[] {0});
        assertEquals("7f8f5f05a103800100", Hex.b2s(req.encode()));
        CardApplicationListReturn isoReturn = new ISO24727.CardApplicationListReturn(Hex.s2b("7f8f6035a12ba0290406e82881c117020409a000000398000500010409a000000410000100010409a0000004100002000182064150495f4f4b9000"));
        List<byte[]> cardApplicationNameList = isoReturn.getCardApplicationNameList();
        assertEquals("[e82881c11702, a00000039800050001, a00000041000010001, a00000041000020001]",
            Buf.toString(cardApplicationNameList));
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
    public void testDataSetList() throws Exception {
        TLV req = ISO24727.dataSetList(new byte[] {0});
        assertEquals("7f8f7105a103800100", Hex.b2s(req.encode()));
        DataSetListReturn isoReturn = new ISO24727.DataSetListReturn(Hex.s2b("7f8f722da123a0211a034343441a07437572446174651a0756657273696f6e1a0843617264496e666f82064150495f4f4b9000"));
        List<String> dataSetNameList = isoReturn.getDataSetNameList();
        assertEquals("[CCD, CurDate, Version, CardInfo]",
            dataSetNameList.toString());
    }

    // DataSetCreate
    // DataSetSelect
    // DataSetDelete

    // DSIList
    public void testDSIList() throws Exception {
        TLV req = ISO24727.dsiList(new byte[] {0});
        assertEquals("7f8f7905a103800100", Hex.b2s(req.encode()));
        DSIListReturn isoReturn = new ISO24727.DSIListReturn(Hex.s2b("7f8f7a11a107a0051a0343434482064150495f4f4b9000"));
        List<String> dsiNameList = isoReturn.getDSINameList();
        assertEquals("[CCD]",
            dsiNameList.toString());
    }

    // DSICreate
    // DSIDelete
    // DSIRead
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
    public void testDIDList() throws Exception {
        TLV req = ISO24727.didList(new byte[] {0});
        assertEquals("7f901105a103800100", Hex.b2s(req.encode()));
        DIDListReturn isoReturn = new ISO24727.DIDListReturn(Hex.s2b("7f901250a146a0441a0231461a0232301a0232341a0232351a0232361a0233301a0233311a0233321a0233331a0233411a0235321a0235331a0235411a0235421a0235431a0235441a02364882064150495f4f4b9000"));
        List<String> didList = isoReturn.getDIDNameList();
        assertEquals("[1F, 20, 24, 25, 26, 30, 31, 32, 33, 3A, 52, 53, 5A, 5B, 5C, 5D, 6H]",
            didList.toString());
    }

    // DIDCreate
    // DIDGet
    // DIDUpdate
    // DIDDelete

    // DIDAuthenticate
    // ===== Authorization Service =====
    // ACLList
    // ACLModify


    public static void main(String[] args) throws Exception {
        List<CardTerminal> terms = TerminalFactory.getDefault().terminals().list(State.CARD_PRESENT);
        if (terms.size() != 1) {
            return;
        }

        SCIOSmartcard sc = new SCIOSmartcard(terms.get(0));
        sc.setDebug(true);
        ISO24727Smartcard iso24727 = new ISO24727Smartcard(sc);
        iso24727.cardApplicationConnect(ISO24727Smartcard.AID_ALPHA);

        List<byte[]> cardAppList = iso24727.cardApplicationList();
        System.out.println(Buf.toString(cardAppList));

        List<String> didList = iso24727.didList(ISO24727Smartcard.AID_ALPHA);
        System.out.println(didList);

        List<String> dataSetList = iso24727.dataSetList(ISO24727Smartcard.AID_ALPHA);
        System.out.println(dataSetList);
        String dataSetName = dataSetList.get(0);

        List<String> dsiList = iso24727.dsiList(ISO24727Smartcard.AID_ALPHA, dataSetName);
        System.out.println(dsiList);
    }
}