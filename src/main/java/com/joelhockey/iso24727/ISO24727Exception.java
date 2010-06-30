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

public class ISO24727Exception extends Exception {
    private static final long serialVersionUID = 0xEDE9713D79048848L;

    private String action;
    private int sw;
    private String returnCode;

    public ISO24727Exception(String message, String action, int sw, String returnCode) {
        super(String.format("%s, action=%s, sw=0x%04x, returnCode=[%s]", message, action, sw, returnCode));
        this.action = action;
        this.sw = sw;
        this.returnCode = returnCode;
    }
    public String getAction() { return action; }
    public int getSW() { return sw; }
    public String getReturnCode() { return returnCode; }
}
