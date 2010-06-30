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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.joelhockey.codec.Hex;
import com.joelhockey.codec.TLV;

public class ISO24727 {
    public static final String AID_ALPHA = "E82881C11702";
    public static final String RETURN_CODE_API_OK = "API_OK";

    public static class ISO24727Return {
        private int sw;
        protected TLV tlv;
        private String returnCode;

        public ISO24727Return(byte[] apdu, String action, int tag) throws ISO24727Exception {
            this(apdu, action, tag, RETURN_CODE_API_OK);
        }
        public ISO24727Return(byte[] apdu, String action, int tag, String expectedReturnCode) throws ISO24727Exception {
            if (apdu.length < 2) {
                throw new ISO24727Exception("Invalid APDU: " + Hex.b2s(apdu), action, 0x6f00, null);
            }

            sw = (apdu[apdu.length - 2] & 0xff) << 8 | (apdu[apdu.length - 1] & 0xff);

            if (sw != 0x9000) {
                throw new ISO24727Exception("Expected SW!=0x9000, apdu: " + Hex.b2s(apdu), action, sw, null);
            }

            if (apdu.length == 2) {
                throw new ISO24727Exception("No data returned in apdu", action, sw, null);
            }

            try {
                tlv = new TLV(apdu);
            } catch (Exception e) {
                throw new ISO24727Exception(e.getMessage(), action, sw, null);
            }

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
                new TLV(0xa0, 0, // CardApplicationPathInfo
                    ifdName == null ? null : new TLV(0x80, 3, ifdName.getBytes()), // ifdName UTF8String
                    new TLV(0x80, 5, aid) // CardApplicationName ApplicationIdentifierAPPLICATION 15] OCTET STRING
                )
            ),
            new TLV(0x80, 1, new byte[] {0}) // exclusiveUse BOOLEAN
        );
    }
    public static class CardApplicationConnectReturn extends ISO24727Return {
        public CardApplicationConnectReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "CardApplicationConnect", 2008);
        }
        public byte[] getConnectionHandle() { return tlv.get(-2).get(0).getv(); }
    }

    // CardApplicationStartSession
    public static byte[] cardApplicationStartSession(byte[] connectionHandle, int didScope, byte[] didName, byte[] didAuthData) {
        return TLV.encode(0x60, 2011,
            new TLV(0xa0, 1, // CardApplicationStartSessionArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0xa0, 1, new TLV(0x80, didScope, (byte[]) null)), // didScope EXPLICIT0] -> IMPLICIT0 (local) / 1 (global)] NULL
                new TLV(0x80, 2, didName),
                new TLV(0x80, 3, didAuthData)
            )
        );
    }
    public static class CardApplicationStartSessionReturn extends ISO24727Return {
        public CardApplicationStartSessionReturn(byte[] apdu, String expectedReturnCode) throws ISO24727Exception {
            super(apdu, "CardApplicationStartSession", 2012, expectedReturnCode);
        }
        public CardApplicationStartSessionReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "CardApplicationStartSession", 2012);
        }
        public TLV getAuthProtocolData() { return tlv.get(-2).get(0).get(0); }
    }

    // CardApplicationList
    public static byte[] cardApplicationList(byte[] connectionHandle) {
        return TLV.encode(0x60, 2015,
            new TLV(0xa0, 1, // CardApplicationSListArgument
                new TLV(0x80, 0, connectionHandle) // connectionHandle
            )
        );
    }
    public static class CardApplicationListReturn extends ISO24727Return {
        public CardApplicationListReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "CardApplicationList", 2016);
        }
        public List<byte[]> getCardApplicationNameList() {
            List<byte[]> result = new ArrayList<byte[]>();
            for (TLV aid : tlv.get(0).get(0).split()) {
                result.add(aid.getv());
            }
            return result;
        }
    }

    // DIDAuthenticate
    public static byte[] didAuthenticate(byte[] connectionHandle, int didScope, String didName, byte[] didAuthData) {
        return TLV.encode(0x60, 2075,
            new TLV(0xa0, 1, // DIDAuthenticateArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0xa0, 1, new TLV(0x80, didScope, (byte[]) null)), // didScope EXPLICIT0] -> IMPLICIT0 (local) / 1 (global)] NULL
                new TLV(0x80, 2, didName.getBytes()),
                new TLV(0x80, 3, didAuthData)
            )
        );
    }
    public static class DIDAuthenticateReturn extends ISO24727Return {
        public DIDAuthenticateReturn(byte[] apdu, String expectedReturnCode) throws ISO24727Exception {
            super(apdu, "DIDAuthenticate", 2076, expectedReturnCode);
        }
        public DIDAuthenticateReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "DIDAuthenticate", 2076);
        }
        public TLV getAuthProtocolData() { return tlv.get(-2).get(0).get(0); }
    }

    // DIDGet
    public static byte[] didGet(byte[] connectionHandle, int didScope, String didName) {
        return TLV.encode(0x60, 2069,
            new TLV(0xa0, 1, // DIDAuthenticateArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0xa0, 1, new TLV(0x80, didScope, (byte[]) null)), // didScope EXPLICIT0] -> IMPLICIT0 (local) / 1 (global)] NULL
                new TLV(0x80, 2, didName.getBytes())
            )
        );
    }
    public static class DIDGetReturn extends ISO24727Return {
        public DIDGetReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "DIDGet", 2070);
        }
        public TLV getMarker() { return tlv.get(-2).get(0).get(4); }
    }

    // ACLList
    public static byte[] aclListDataSet(byte[] connectionHandle, String dataSet) {
        return TLV.encode(0x60, 2077,
            new TLV(0xa0, 1, // ACLListArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0x80, 1, "DATA-SET".getBytes()), // TargetType
                new TLV(0xa0, 2, new TLV(0x80, 0, dataSet.getBytes())) // TargetName
            )
        );
    }

    public static byte[] aclListDID(byte[] connectionHandle, String didName) {
        return TLV.encode(0x60, 2077,
            new TLV(0xa0, 1, // ACLListArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0x80, 1, "DIFFERENTIAL-IDENTITY".getBytes()), // TargetType
                new TLV(0xa0, 2, new TLV(0x80, 1, didName.getBytes())) // TargetName
            )
        );
    }

    public static byte[] aclListApp(byte[] connectionHandle, byte[] aid) {
        return TLV.encode(0x60, 2077,
            new TLV(0xa0, 1, // ACLListArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0x80, 1, "CARD-APPLICATION".getBytes()), // TargetType
                new TLV(0xa0, 2, new TLV(0x80, 2, aid)) // TargetName
            )
        );
    }

    public static class ACLListReturn extends ISO24727Return {
        public ACLListReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "ACLList", 2078);
        }
        public TLV getAcl() { return tlv.get(-2).get(0); }
    }

    // DataSetSelect
    public static byte[] dataSetSelect(byte[] connectionHandle, String dataSetName) {
        return TLV.encode(0x60, 2037,
            new TLV(0xa0, 1, // DataSetSelectArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0x80, 1, dataSetName.getBytes()) // DataSetName
            )
        );
    }
    public static class DataSetSelectReturn extends ISO24727Return {
        public DataSetSelectReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "DataSetSelect", 2038);
        }
    }

    // DSIRead
    public static byte[] dsiRead(byte[] connectionHandle, String dsiName) {
        return TLV.encode(0x60, 2049,
            new TLV(0xa0, 1, // DSIReadArgument
                new TLV(0x80, 0, connectionHandle), // connectionHandle
                new TLV(0x80, 1, dsiName.getBytes()) // DSIName
            )
        );
    }
    public static class DSIReadReturn extends ISO24727Return {
        public DSIReadReturn(byte[] apdu) throws ISO24727Exception {
            super(apdu, "DSIRead", 2050);
        }
        public TLV getDsi() { return tlv.get(-2).get(0); }
    }

// AccessControlList ::= SET OF AccessRule
// AccessRule ::= SEQUENCE {
//   cardApplicationService [0] IMPLICIT CardApplicationServiceName,
//   action                 [1] EXPLICIT ActionName,
//   securityCondition      [2] EXPLICIT SecurityCondition
// }
// CardApplicationServiceName ::= VisibleString
// ActionName ::= CHOICE {
//   apiAccessEntryPoint               [0] IMPLICIT APIAccessEntryPointName,
//   connectionServiceAction           [1] IMPLICIT ConnectionServiceActionName,
//   cardApplicationServiceAction      [2] IMPLICIT CardApplicationServiceActionName,
//   namedDataServiceAction            [3] IMPLICIT NamedDataServiceActionName,
//   cryptographicServiceAction        [4] IMPLICIT CryptographicServiceActionName,
//   differentialIdentityServiceAction [5] IMPLICIT DifferentialIdentityServiceActionName,
//   authorizationServiceAction        [6] IMPLICIT AuthorizationServiceActionName
// }
// SecurityCondition ::= CHOICE {
//   didAuthentication [0] IMPLICIT DifferentialIdentityAuthenticationState,
//   always            [1] IMPLICIT BOOLEAN (TRUE),
//   never             [2] IMPLICIT BOOLEAN (FALSE),
//   not               [3] EXPLICIT SecurityCondition,
//   and               [4] IMPLICIT SEQUENCE SIZE (1..size-max-SecurityCondition) OF SecurityCondition,
//   or                [5] SEQUENCE SIZE (1..size-max-SecurityCondition) OF SecurityCondition
// }
// DifferentialIdentityAuthenticationState ::= SEQUENCE {
//   dIDName  [0] IMPLICIT DIDName,
//   dIDScope [1] EXPLICIT DIDScope,
//   dIDState [2] IMPLICIT BOOLEAN
// }
// DIDName ::= Name
// Name ::= VisibleString (SIZE(1..size-max-NameLength))
// DIDScope ::= CHOICE {
//   local  [0] IMPLICIT NULL,
//   global [1] IMPLICIT NULL
// }
    private static void formatSecurityCondition(StringBuilder sb, TLV tlv, int indentLevel) {
        char[] indent = new char[indentLevel * 2];
        Arrays.fill(indent, ' ');
        if (tlv.gett() == 0) { // didAuthentication
            sb.append(tlv.get(2).getv()[0] == 0 ? "-" : "+"); // didState 0=off, 1=on
            sb.append(tlv.get(1).get(0).gett() == 0 ? "l:" : "g:"); // didScope 0=local, 1=global
            sb.append(new String(tlv.get(0).getv())); // didName
        } else if (tlv.gett() == 1) { // always
            sb.append("always");
        } else if (tlv.gett() == 2) { // never
            sb.append("never");
        } else if (tlv.gett() == 3) { // not
            sb.append("!(");
            formatSecurityCondition(sb, tlv.get(0), indentLevel + 1);
            sb.append(")");
        } else if (tlv.gett() == 4 || tlv.gett() == 5) { // 4=and, 5=or
            String andor = tlv.gett() == 4 ? "and" : "or";
            if (tlv.split().size() > 1) {
                sb.append("(\n  ").append(indent);
                andor = String.format("\n%s%s\n%s  ", indent, andor, indent);
            }
            String sep = "";
            for (TLV sc : tlv.split()) {
                formatSecurityCondition(sb, sc, indentLevel + 1);
                sb.append(sep);
                sep = andor;
            }
            if (tlv.split().size() > 1) {
                sb.append("\n").append(indent);
            }
        } else {
            throw new IllegalArgumentException("Error: Unknown SecurityCondition tag: " + tlv.gett());
        }
    }

    public static String formatACL(TLV acl) {
        StringBuilder sb = new StringBuilder();
        // check if TLV is SET (AccessControlList) or SEQUENCE (AccessRule)
        int t = acl.getcc() | acl.gett();
        List<TLV> rules;
        if (t == 0x31 || t == 0xa0) { // SET or other context-specific constructed [0] IMPLICIT (bloody AUTO tags!)
            rules = acl.split();
        } else if (acl.gett() == 0x10) { // SEQUENCE means this is a single AccessRule
            rules = new ArrayList<TLV>();
            rules.add(acl);
        } else {
            throw new IllegalArgumentException("could not parse acl\n" + acl.dump());
        }

        String sep = "";
        for (TLV rule : rules) {
            TLV cas = rule.get(0); // card application service
            TLV action = rule.get(1).get(0); // action is wrapped in [1] EXPLICIT
            TLV sc = rule.get(2).get(0); // SecurityCondition is wrapped in [2] EXPLICIT
            String newline = " ";
            if ((sc.gett()  == 4 || sc.gett() == 5) && sc.split().size() > 1) {  // and/or
                newline = "\n  ";
            }
            sb.append(new String(cas.getv()));
            sb.append('.').append(new String(action.getv()));
            sb.append(newline);
            formatSecurityCondition(sb, sc, 1);
            sb.append(sep);
            sep = "\n";
        }
        return sb.toString();
    }
}