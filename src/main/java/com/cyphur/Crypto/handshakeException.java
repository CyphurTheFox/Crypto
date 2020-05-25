/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.cyphur.Crypto;

/**
 *
 * @author Cyphur
 */
public class handshakeException extends Exception {

    /**
     * Creates a new instance of <code>handshakeException</code> without detail
     * message.
     */
    public handshakeException() {
    }

    /**
     * Constructs an instance of <code>handshakeException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public handshakeException(String msg) {
        super(msg);
    }
}
