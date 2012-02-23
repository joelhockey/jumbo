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

/**
 * ISO24727 Exception
 */
public class ISO24727Exception extends Exception {
    private static final long serialVersionUID = 0xEDE9713D79048848L;

    private String action;
    private int sw;
    private String returnCode;

    /**
     * Create ISO24727 exception
     * @param message message
     * @param action action being executed
     * @param sw status word
     * @param returnCode return code
     */
    public ISO24727Exception(String message, String action, int sw, String returnCode) {
        super(String.format("%s, action=%s, sw=0x%04x, returnCode=[%s]", message, action, sw, returnCode));
        this.action = action;
        this.sw = sw;
        this.returnCode = returnCode;
    }
    /** @return action */
    public String getAction() { return action; }
    /** @return status word */
    public int getSW() { return sw; }
    /** @return return code */
    public String getReturnCode() { return returnCode; }
}
