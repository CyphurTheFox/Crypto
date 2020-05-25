/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.cyphur.Crypto;

/**
 *
 * @author Cyphur
 * 
 */
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

class failedHandshakeException extends handshakeException{
    public failedHandshakeException(String msg){
        super(msg);
    }
}
class missingHandshakeException extends handshakeException{
    public missingHandshakeException(String msg){
        super(msg);
    }
}
/**
 * CyphurCrypt is a tool developed to simplifiy the use of the RSA and AES algorithims to
 * establish a secure connection for data transfer between two parties. The implementation is designed
 * to be reasonably secure, however it should be noted that this class does not handle
 * the actual transmission of data between two parties. That is left to the user.
 * @author Cyphur
 */
public class CyphurCrypt {
    private final AESToolKit AES; //AES Shared Key Encryption System.
    private final RSAToolKit Public;  //RSA Encryption containing Non-Local Keys
    private final RSAToolKit Private; //RSA Encryption containing Local Keys
    private final SecureRandom rand;
    private byte BlockSize;
    /**
     * Indicates that the user should send the returned packet back to the source.
     * 
     * sendBack is a flag used in conjunction with the parseMessage() method. 
     * The flag is set whenever a returned byte array is intended to be sent back
     * to the original sender of the recieved Message.
     */
    public boolean sendBack;
    /**
     * Indicates that the returned packet is a message from the source.
     * 
     * The messageReceived flag is used in conjunction with the parseMessage() method.
     * The Flag is set when the parsed message is a message from the paired instance
     * of CyphurCrypt.
     */
    public boolean messageReceived;
    /**
     * Indicates that a successful handshake has been performed.
     * 
     * connectionEstablished is a flag used to indicate whether or not a full key 
     * exchange has occured and a secure encrypted tunnel is use. The sendMessage()
     * method will always throw an exception until this flag is set.
     */
    public boolean connectionEstablished;   
    /**
     * Prevents accidental modification of the keys.
     * 
     * The locked Flag is set by default, however it can be unset by the user. 
     * This flag is used in conjunction with connectionEstablished flag. When
     * both of these flags are set, the system will discard any new key exchange
     * packets.
     */
    public boolean locked;  
    private byte[] myID;
    private byte[] otherID;
    
    

    private byte[] bbGetBytes(ByteBuffer bb){
        byte[] output = new byte[bb.capacity()];
        bb.position(0);
        bb.get(output);
        return output;
    }
    private byte[] shortAsBytes(short i){
        byte[] out = new byte[2];
        ByteBuffer bb = ByteBuffer.wrap(out);
        bb.putInt(i);
        return out;
    }
    private short ByteArraytoShort(byte[] i){
        ByteBuffer bb = ByteBuffer.wrap(i);
        return bb.getShort();
    }
    
    public CyphurCrypt(){
        // create Crypto Objects
        AES = new AESToolKit();
        Public = new RSAToolKit();
        Private = new RSAToolKit();
        rand = new SecureRandom();
        BlockSize = (byte) ((rand.nextInt() % 12) + 6);
        
        //create local Keys
        Private.generateKeys();
        AES.generateKey(192);
        
        //generate Identifier
        myID = new byte[10];
        otherID = new byte[10];
        rand.nextBytes(myID);
        
        //reset Flags
        sendBack = false;
        connectionEstablished = false;
        
        //set Flags
        locked = true;
    }
    /**
     * Generates an instance of CyphurCrypt with an existing AESToolkit.
     * @param ServerKey Existing AESToolKit
     */
    public CyphurCrypt(AESToolKit ServerKey){
        // create Crypto Objects
        AES = ServerKey;
        Public = new RSAToolKit();
        Private = new RSAToolKit();
        rand = new SecureRandom();
        BlockSize = (byte) ((rand.nextInt() % 12) + 6);
        
        //create local Keys
        Private.generateKeys();
        
        //generate Identifier
        myID = new byte[10];
        otherID = new byte[10];
        rand.nextBytes(myID);
        
        //reset Flags
        sendBack = false;
        connectionEstablished = false;
        
        //set Flags
        locked = true;
    }
    
    /**
     * generateGreeting is used to generate the first packet in a handshake key
     * exchange.
     * @return A byte[] that should be sent to another instance of CyphurCrypt to
     * initiate key exchange
     */
    public byte[] generateGreeting(){
        BigInteger[] keys = Private.getPublicKey();
        byte[] e = keys[0].toByteArray();
        byte[] n = keys[1].toByteArray();
        short elen = (short) e.length;
        short nlen = (short) n.length;
        ByteBuffer bb = ByteBuffer.allocate(elen + nlen + 5);
        bb.put((byte) 0xFE).putShort(elen).put(e).putShort(nlen).put(n);
        return bbGetBytes(bb);
    }
    /**
     * sendMessage is intended to be used once a full handshake has been performed.
     * It is used to encrypt a message using the AES algorithim.
     * @param message 
     * The message to be sent to the other user. Must be formatted as a byte[]
     * 
     * @return
     * An encrypted byte[] to be sent to another instance of CyphurCrypt
     * 
     * @throws missingHandshakeException
     * This exception is thrown when the user attempts to encrypt a message however
     * a key exchange has not yet occured.
     * 
     */
    public byte[] sendMessage(byte[] message) throws missingHandshakeException{
        if(!connectionEstablished){
            throw new missingHandshakeException("Handshake not performed yet! Connect with other system to begin communication.");
        }
        byte[] output;
        
        output = AES.encryptData(message);
        ByteBuffer bb = ByteBuffer.allocate(output.length+1);
        bb.put((byte) 0x01).put(output);
        
        
        
        return bbGetBytes(bb);
    }
    /**
     * <code>parseMessage</code> is a catch-all for any kind of message that is coming from
     * another instance of CyphurCrypt. The method parses a given message and sets
     * relevant flags based on what the user needs to do with the returned value.
     * @param message
     * This is the incoming packet from another instance of <code>CyphurCrypt</code>
     * 
     * @return
     * The return can vary based on the input packet. It takes the form of
     * a byte[] which should either be sent back to the sender of the original packet 
     * or parsed as a decrypted message from the sender. The relevant action to take
     * will be indicated with the <code>sendBack</code> or <code>messageReceived</code> flags
     * 
     * @throws handshakeException 
     * This method throws either <code> missingHandshakeException</code> to indicate that
     * a handshake has not yet been performed with another isntance of <code>CyphurCrypt</code> or it throws
     * <code> failedHandshakeException </code> to indicate that the handshake failed.
     */
    public byte[] parseMessage(byte[] message) throws handshakeException{
        try {
            ByteBuffer bb =  ByteBuffer.wrap(message);
            ByteBuffer bbo;
            byte op = bb.get();
            short elen, nlen;
            byte[] e, n;
            String Handshake;
            BigInteger[] Encrypted;
            sendBack = false;
            messageReceived = false;
            byte[] cipher;
            byte[] buffer;
            byte[] data;
            ByteBuffer deconstruct;
            if(op != (byte) 0x01 && locked && connectionEstablished){
                return new byte[1];
            }
            switch (op){
                case (byte) 0xFE:
                    
                    /*retrieving constants */
                    
                    /* get e */
                    elen = bb.getShort(); 
                    e = new byte[elen];
                    bb.get(e);
                    
                    /* get n */
                    nlen = bb.getShort();
                    n = new byte[nlen];
                    bb.get(n);
                    
                    /* convert e & n to BigInts */
                    BigInteger Be = new BigInteger(e);
                    BigInteger Bn = new BigInteger(n);  
                    
                    /* set the key */
                    Public.setPublicKey(Be,Bn);
                    
                    /* generate a handshake */
                    Handshake = AES.generateHandshake(1);
//                    System.out.println(Handshake);
                    
                    /* encrypt the handshake */
                        Encrypted = Public.RSAencryptString(Handshake);
                        
                        /* determine longest bigInt */
                        int longest = 0;
                        for(BigInteger I : Encrypted){
                            if (I.bitLength() > longest){
                                longest = I.bitLength();
                            }
                        }
                        
                        /* convert array of BigInts to 2d array of bytes */
                        
                        /* byte[The BigInts] [The longest Big Int]; */
                        byte[][] sBytes = new byte[Encrypted.length][(longest/8)+1];
                        
                        /* for each big int, store it in the 2d array */
                        for(int i = 0; i < Encrypted.length; ++i){
                            sBytes[i] = Encrypted[i].toByteArray();
                        }
                        
                        /* allocate a byte buffer */
                        bbo = ByteBuffer.allocate(
                                (sBytes.length*((longest/8)+3)) /* byte array */
                                        + 1 /* opcode byte */
                                        + 4 ); /* count integer
                        /* put opcode byte */
                        bbo.put((byte) 0x07);
                        /* put the count integer */
                        
                        bbo.putInt(sBytes.length);
                        
                        /* put the bigInts, sequentially */
                        for(byte[] byt : sBytes){
                            short bytLen = (short) byt.length;
                            bbo.putShort(bytLen);
                            bbo.put(byt);
                        }
                        /* packet gets sent back */
                        sendBack = true;
                        
                        /* return the bytes */
                        return bbGetBytes(bbo);
                        
                        
                case (byte) 0x07:
                    int count;
                    count = bb.getInt();
                    Encrypted = new BigInteger[count];
                    for(int i = 0; i < count; ++i){
                        short len = bb.getShort();
                        byte[] buf = new byte[len];
                        bb.get(buf);
                        Encrypted[i] = new BigInteger(buf);
                    }
                    Handshake = Private.RSAdecryptString(Encrypted, 3);
//                    System.out.println(Handshake);
                    AES.parseHandshake(Handshake);
                    buffer = new byte[11];
                    ByteBuffer construct = ByteBuffer.wrap(buffer);
                    construct.put((byte) 0xEE);
                    construct.put(myID);
                    byte[] ret = 
                        AES.encryptData(buffer);
                    buffer = new byte[ret.length + 1];
//                    System.out.println();
//                    for(byte by : ret){
//                        System.out.print(by + "|");
//                    }
                    construct = ByteBuffer.allocate(ret.length + 1);
                    construct.put((byte) 0xEE);
                    construct.put(ret);
                    sendBack = true;
                    return bbGetBytes(construct);
                case (byte) 0xEE:
                    cipher = new byte[bb.remaining()];
                    bb.get(cipher);
//                    System.out.println();
//                    for(byte by : cipher){
//                        System.out.print(by + "|");
//                    }
                    data = AES.decryptData(cipher);
                    deconstruct = ByteBuffer.wrap(data);
                    if(deconstruct.get() != (byte) 0xEE){
                        throw new failedHandshakeException("Handshake Failed! Keys Do Not Match");
                    } else {
                        deconstruct.get(otherID);
                        connectionEstablished = true;
                        ByteBuffer ID = ByteBuffer.allocate(1+myID.length);
                        ID.put((byte)0xEE).put(myID);
                        buffer = AES.encryptData(bbGetBytes(ID));
                        bbo = ByteBuffer.allocate(buffer.length +1);
                        bbo.put((byte) 0xEF).put(buffer);
                        sendBack = true;
                        return bbGetBytes(bbo);
                    }
                case (byte) 0xEF:
                    
                    cipher = new byte[bb.remaining()];
                    bb.get(cipher);
//                    System.out.println();
//                    for(byte by : cipher){
//                        System.out.print(by + "|");
//                    }
                    data = AES.decryptData(cipher);
                    
                    deconstruct = ByteBuffer.wrap(data);
                    if(deconstruct.get() != (byte) 0xEE){
                        throw new failedHandshakeException("Handshake Failed! Keys Do Not Match");
                    } else {
                        deconstruct.get(otherID);
                        connectionEstablished = true;
                    }
                    return new byte[1];
                    
                    
                    
                    
                case (byte) 0x01:
                    if(!connectionEstablished){
                        throw new missingHandshakeException("Recieved packet is a data packet, however the key exchange has not been completed!");
                    }
                    cipher = new byte[bb.remaining()];
                    
                    /* get the bytes into a byte array */
                    bb.get(cipher);
                    
                    /* decryption */
                    data = AES.decryptData(cipher);
                    
                    messageReceived = true; 
                    
                    return data;
                    
                    
            }   
        } catch (MissingPrivateKeyException | MissingPublicKeyException ex) {
            Logger.getLogger(CyphurCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] tempoutvar = {12, 5};
        return tempoutvar;
    }
    
    
    
}

/* handshake stages:

Client generates & sends RSA key;

Server recieves; sends back AES key-RSA encrypted;

Client decrypts AES key; generates confirm packet

server decrypts confirm packet; sends own confirm packet

client recieves confirm packet, connection established.

Comms may commence

*/