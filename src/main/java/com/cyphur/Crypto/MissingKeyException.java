/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.cyphur.Crypto;

/**
 *
 * @author TNT
 */
public class MissingKeyException extends Exception {

    /**
     * Creates a new instance of <code>MissingArgumentException</code> without
     * detail message.
     */
    public MissingKeyException() {
    }

    /**
     * Constructs an instance of <code>MissingArgumentException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public MissingKeyException(String msg) {
        super(msg);
    }
}