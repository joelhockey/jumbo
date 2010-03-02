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

import com.joelhockey.codec.Hex;
import com.joelhockey.codec.TLV;

public class ISO24727 {
    public static class ISO24727Return {
       
        private int sw;
        protected TLV tlv;
        private String returnCode;
        
        public ISO24727Return(byte[] apdu, String action, int tag) throws ISO24727Exception {
            this(apdu, action, tag, "API_OK");
        }
        public ISO24727Return(byte[] apdu, String action, int tag, String expectedReturnCode) throws ISO24727Exception {
            if (apdu.length < 2) {
                throw new ISO24727Exception("Invalid APDU: " + Hex.b2s(apdu), action, 0x6f00, null);
            }

            sw = (apdu[-2] & 0xff) << 8 | (apdu[-1] & 0xff);
        
            if (sw != 0x9000) {
                throw new ISO24727Exception("Expected SW!=0x9000, apdu: " + Hex.b2s(apdu), action, sw, null);
            }
            
            tlv = new TLV(apdu);
            if (tlv.getcc() != 0x60 || tlv.gett() != tag) { 
                throw new ISO24727Exception(String.format("%s Expected [APPLICTION %s], got TLV:\n%s", action, tag, tlv.dump()),
                        action, sw, null);
            }

            returnCode = new String(tlv.get(-1).getv());
            if (!returnCode.equals(expectedReturnCode)) {
                throw new ISO24727Exception(String.format("Expected [%s]", expectedReturnCode), action, sw, returnCode);
            }
        }
        
        public int getSW() { return sw; }
        public TLV getTLV() { return tlv; }
        public String getReturnCode() { return returnCode; }
    }
    
    // CardApplicationConnect
    public static byte[] cardApplicationConnect(String ifdName, byte[] aid) {
        return
        TLV.encode(0x60, 2007, 
            new TLV(0xa0, 1, // CardApplicationConnectArgument
                TLV.encode(0xa0, 0, // CardApplicationPathInfo
                    ifdName == null ? new byte[0] : TLV.encode(0x80, 3, ifdName.getBytes()), // ifdName UTF8String
                    TLV.encode(0x80, 5, aid) // CardApplicationName ApplicationIdentifier [APPLICATION 15] OCTET STRING
                )
            ),
            new TLV(0x80, 1, new byte[] {0}) // exclusiveUse BOOLEAN
        );
    }

    public static class CardApplicationConnectReturn extends ISO24727Return {
        public CardApplicationConnectReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "CardApplicationConnect", 2008);
        }
        public byte[] getConnectionHandle() {
            return tlv.get(-2).get(0).getv();
        }
    }
    
/*
 * 
     

# CardApplicationStartSession
def cardApplicationStartSession(connectionHandle, didScope, didName, didAuthData):
    return TLV.encode(0x60, 2011, [
        TLV.encode(0xa0, 1, [ # CardApplicationStartSessionArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0xa0, 1, TLV.encode(0x80, didScope, '')), # didScope EXPLICIT [0] -> IMPLICIT [0 (local) / 1 (global)] NULL
            TLV.encode(0x80, 2, didName),
            TLV.encode(0x80, 3, didAuthData),
        ]),
    ])

class CardApplicationStartSessionReturn(ISO24727Return):
    def __init__(self, apdu, expectedReturnCode=RETURN_CODE_API_OK):
        ISO24727Return.__init__(self, apdu, 'CardApplicationStartSession', 2012, expectedReturnCode)

    def getAuthProtocolData(self):
        return self.tlv.get(-2).get(0).get(0)

# CardApplicationList
def cardApplicationList(connectionHandle):
    return TLV.encode(0x60, 2015, [
        TLV.encode(0xa0, 1, [ # CardApplicationSListArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
        ]),
    ])

class CardApplicationListReturn(ISO24727Return):
    def __init__(self, apdu):
        ISO24727Return.__init__(self, apdu, 'CardApplicationList', 2016)

    def getCardApplicationNameList(self):
        return [tlv.getv() for tlv in self.tlv.get(0).get(0).split()]

# DIDAuthenticate
def didAuthenticate(connectionHandle, didScope, didName, didAuthData):
    return TLV.encode(0x60, 2075, [
        TLV.encode(0xa0, 1, [ # DIDAuthenticateArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0xa0, 1, TLV.encode(0x80, didScope, '')), # didScope EXPLICIT [0] -> IMPLICIT [0 (local) / 1 (global)] NULL
            TLV.encode(0x80, 2, didName),
            TLV.encode(0x80, 3, didAuthData),
        ]),
    ])

class DIDAuthenticateReturn(ISO24727Return):
    def __init__(self, apdu, expectedReturnCode=RETURN_CODE_API_OK):
        ISO24727Return.__init__(self, apdu, 'DIDAuthenticate', 2076, expectedReturnCode)

    def getAuthProtocolData(self):
        return self.tlv.get(-2).get(0).get(0)

# DIDGet
def didGet(connectionHandle, didScope, didName):
    return TLV.encode(0x60, 2069, [
        TLV.encode(0xa0, 1, [ # DIDAuthenticateArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0xa0, 1, TLV.encode(0x80, didScope, '')), # didScope EXPLICIT [0] -> IMPLICIT [0 (local) / 1 (global)] NULL
            TLV.encode(0x80, 2, didName),
        ]),
    ])

class DIDGetReturn(ISO24727Return):
    def __init__(self, apdu):
        ISO24727Return.__init__(self, apdu, 'DIDGet', 2070)

    def getMarker(self):
        return self.tlv.get(-2).get(0).get(4)

# ACLList
def aclListDataSet(connectionHandle, dataSet):
    return TLV.encode(0x60, 2077, [
        TLV.encode(0xa0, 1, [ # ACLListArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0x80, 1, 'DATA-SET'), # TargetType
            TLV.encode(0xa0, 2, TLV.encode(0x80, 0, dataSet)), # TargetName
        ]),
    ])

def aclListDID(connectionHandle, did):
    return TLV.encode(0x60, 2077, [
        TLV.encode(0xa0, 1, [ # ACLListArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0x80, 1, 'DIFFERENTIAL-IDENTITY'), # TargetType
            TLV.encode(0xa0, 2, TLV.encode(0x80, 1, did)), # TargetName
        ]),
    ])

def aclListApp(connectionHandle, did):
    return TLV.encode(0x60, 2077, [
        TLV.encode(0xa0, 1, [ # ACLListArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0x80, 1, 'CARD-APPLICATION'), # TargetType
            TLV.encode(0xa0, 2, TLV.encode(0x80, 2, did)), # TargetName
        ]),
    ])

class ACLListReturn(ISO24727Return):
    def __init__(self, apdu):
        ISO24727Return.__init__(self, apdu, 'ACLList', 2078)

    def getAcl(self):
        return self.tlv.get(-2).get(0)

# DataSetSelect
def dataSetSelect(connectionHandle, dataSet):
    return TLV.encode(0x60, 2037, [
        TLV.encode(0xa0, 1, [ # DataSetSelectArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0x80, 1, dataSet), # DataSetName
        ]),
    ])

class DataSetSelectReturn(ISO24727Return):
    def __init__(self, apdu):
        ISO24727Return.__init__(self, apdu, 'DataSetSelect', 2038)

# DSIRead
def dsiRead(connectionHandle, dataSet):
    return TLV.encode(0x60, 2049, [
        TLV.encode(0xa0, 1, [ # DSIReadArgument
            TLV.encode(0x80, 0, connectionHandle), # connectionHandle
            TLV.encode(0x80, 1, dataSet), # DSIName
        ]),
    ])

class DSIReadReturn(ISO24727Return):
    def __init__(self, apdu):
        ISO24727Return.__init__(self, apdu, 'DSIRead', 2050)

    def getDsi(self):
        return self.tlv.get(-2).get(0)

        
class SecureMessagingException(Exception):
    def __init__(self, message):
        self.message =  message
    
    def __str__(self):
        return self.message

     

 */
}