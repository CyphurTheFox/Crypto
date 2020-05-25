/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.cyphur.Crypto;


import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;


/**
 *
 * @author Cyphur
 */

class MissingPublicKeyException extends MissingKeyException{}
class MissingPrivateKeyException extends MissingKeyException{}



public class RSAToolKit {  
    private boolean publicKey;
    private boolean privateKey;
    
    private BigInteger e;
    private BigInteger d;
    private BigInteger n;
    private BigInteger prime1;
    private BigInteger prime2;
    
    /*calculate modular Inverse */
    private static BigInteger modInverse(BigInteger a, BigInteger m){         /* not my code. Some black magic F***ery */
        BigInteger m0 = m; 
        BigInteger y = BigInteger.ZERO, x = BigInteger.ONE; 
  
        if (m.equals(BigInteger.ONE)) 
            return BigInteger.ZERO; 
  
        while (a.compareTo(BigInteger.ONE) > 0)
        { 
            // q is quotient 
            BigInteger q = a.divide(m); 
  
            BigInteger t = m; 
  
            // m is remainder now, process 
            // same as Euclid's algo 
            m = a.mod(m); 
            a = t; 
            t = y;
  
            // Update x and y 
            y = x.subtract(q.multiply(y)); 
            x = t; 
        } 
  
        // Make x positive 
        if (x.compareTo(BigInteger.ZERO) < 0) 
            x = x.add(m0); 
  
        return x; 
    } 
    
    
    /* initialization function */
    public RSAToolKit() {
        this.publicKey = false;         /* when initialized, set the indicators of public & privvate keys to false because no keys are generated yet */
        this.privateKey = false;

    }

    /* calculate LCM */
    private BigInteger lcm(BigInteger a, BigInteger b){   
        BigInteger div;
        div = a.multiply(b);
        return div.divide(a.gcd(b));       /* calculate a function that returns the LCM based off of the GCD */
    }
    
    
    
    
    /* generate keys from provided primes */
    public void generateKeys(BigInteger p, BigInteger q){
        prime1 = p;             /* store the provided prime numbers in their respective variables for later */
        prime2 = q;
        BigInteger totient;           /* temp variable for the totient (totient can be used to crack the encryption so it is discarded after being used.) */
        
        n = p.multiply(q);                /* generate modulus factor based off of the prime numbers */
        
        totient = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));        /* calculate the totient of n, which is the LCM of one less than the prime numbers */
        
        e = new BigInteger(64, 15, new SecureRandom());                      /* e is an arbitrary chosen value that is coprime with the totient, really just prime number because im too lazy to check coprime */
        
        d = modInverse(e,totient);      /* calculate the modular inverse of E and the totient. allows the decryption to work */
        
        this.publicKey = true;          /* set variables to indicate that the public and private keys now exist */
        this.privateKey = true;
        
        totient = null; /* discard the totient for security */
    }
    
    
    /* generate keys without provided primes, default bitlength (2048 bit key) */
    public void generateKeys(){
        generateKeys(new BigInteger(1024, 10 , new SecureRandom()),new BigInteger(1024, 10 , new SecureRandom()));
    }
     /* generate keys without provided primes, of a specific bit length */
    public void generateKeys(int bitlength){
        generateKeys(new BigInteger(bitlength/2, 10 , new SecureRandom()),new BigInteger(bitlength/2, 10 , new SecureRandom()));
    }
    
    /* breaks up a string into (blockSize) character groups */
    private String[] breakUpString(String str, int blockSize) {
        String[] Segments = new String [(int) Math.ceil((double) str.length()/blockSize)];
        String buffer = "";
        int j = 0;
        for(int i = 0; i < str.length(); ++i){
            buffer = buffer + str.charAt(i);
            if(buffer.length() == blockSize){
                Segments[j] = buffer;
                buffer = "";
                ++j;
            }
        }
        if(buffer.length() > 0){
            while (buffer.length() < blockSize){
                buffer = buffer + "-";
            }
            Segments[j] = buffer;
        }
        return Segments;
    }
    
    
    /* takes a string, UTF-8 encodes it, then converts the bytes to ints, appends them, and returns the appended int */
    private long stringToLong(String str, int blockSize){
        if(str.length() > blockSize){
            throw new IllegalArgumentException("BlockSize does not equal String Length");
        }
        byte[] b = str.getBytes(StandardCharsets.UTF_8);
        String output = "";
        String temp = "";
        for(int i = 0; i < blockSize; ++i){
            temp = 
                    String.valueOf(
                        Byte.toUnsignedInt(
                            b[i]));
            
            while(temp.length() < 3)
                temp = "0" + temp;
            
            output = output + temp;
            
        }
        return Integer.parseInt(output);
    }
    
    
    /* converts a string to a UTF-8 encoded long array where each long represents 3 characters */
    public long[] stringToLongArray(String str, int blockSize){
        String[] pieces = breakUpString(str, blockSize);
        int count = pieces.length;
        long[] output = new long[count];
        for(int i = 0; i < count; ++i){
            try{
                output[i] = stringToLong(pieces[i], blockSize);
            } catch (IllegalArgumentException e){
                
            }
        }
        return output;
    }
    
    
    /* decodes the 3 character set encoded inside a long in UTF-8 */
    public String stringFromLong(long var, int blockSize){
        String chars = String.valueOf(var);
        String[] sets = new String[blockSize];
        byte[] b = new byte[blockSize];
        
        int j = 2;
        for(int i  = chars.length()-1; i >= 0; --i){
            if(sets[j] == "null" || sets[j] == null){
                sets[j] = String.valueOf(chars.charAt(i));
            } else {
            sets[j] = 
                    chars.charAt(i)
                    + sets[j];
            }
            if(sets[j].length() >= blockSize){
                --j;
            }
        }
        for(int i = 0; i < 3; ++i){
            b[i] = (byte) Integer.parseInt(sets[i]);
        }
        return new String(b,StandardCharsets.UTF_8);
    }
    
    
    /* Produces the string encoded by a set of long variables stored in an array */
    public String stringFromLongArray(long[] arr, int blockSize){
        String output = "";
        for(long el: arr) {
            output = output + stringFromLong(el, blockSize);
        }
        return output;
    }
    
    
    
    /* RSA Encryption Function */
    public BigInteger[] RSAencryptString(String str, int blockSize) throws MissingPublicKeyException{
        if(!publicKey){
            throw new MissingPublicKeyException();
         }
        if (blockSize < 3){
            throw new IllegalArgumentException();
        }
        
        
        long[] l = this.stringToLongArray(str, blockSize);
        int count = l.length;
        BigInteger[] o = new BigInteger[count];
        
        BigInteger B = new BigInteger("0");
        
        for (int i  = 0; i < count; ++i){
            if(n.compareTo(BigInteger.valueOf(l[i])) <= 0){
                throw new IllegalArgumentException("Key Not Big Enough For Selected Block Size");
            }
            B = BigInteger.valueOf(l[i]);
            B = B.modPow(e,n);
            o[i] = B;
        }
        return o;   
            
    }
    /* default block Size Function */
    public BigInteger[] RSAencryptString(String str) throws MissingPublicKeyException{
        return RSAencryptString(str, 3);
    }
    
    
    /* RSA decryption Function */
    public String RSAdecryptString(BigInteger[] arr, int blockSize) throws MissingPrivateKeyException{
        
        if(!privateKey){
            throw new MissingPrivateKeyException();
         }
        
        if (blockSize < 3){
            throw new IllegalArgumentException();
        }
        
        int count = arr.length;
        long[] dcrypt = new long[count];
        
        BigInteger B = new BigInteger("0");
        
        for(int i = 0; i < count; ++i){
            B = arr[i];
            
            B = B.modPow(d,n);
            
            dcrypt[i] = B.longValueExact();
            
        }
        return stringFromLongArray(dcrypt, blockSize);
        
    }
    
    
    
    /* functions to set keys and get keys */
    public void setPrivateKey(long exponent, long modulo){
        if(publicKey && n.longValue() != modulo)
            publicKey = false;
        
        d = BigInteger.valueOf(exponent);
        n = BigInteger.valueOf(modulo);
        privateKey = true;
    }
    public void setPrivateKey(BigInteger exponent, BigInteger modulo){
        if(publicKey && n != modulo)
            publicKey = false;
        
        d = exponent;
        n = modulo;
        privateKey = true;
    }
    public void setPublicKey(long exponent, long modulo){
        if(privateKey && n.longValue() != modulo)
            privateKey = false;
        
        e = BigInteger.valueOf(exponent);
        n = BigInteger.valueOf(modulo);
        publicKey = true;
        
    }
    public void setPublicKey(BigInteger exponent, BigInteger modulo){
        if(privateKey && !n.equals(modulo))
            privateKey = false;
        
        e = exponent;
        n = modulo;
        publicKey = true;
        
    }
    
    public BigInteger[] getPrivateKey(){
        return new BigInteger[] {d,n};
    }
    
    public BigInteger[] getPublicKey(){
        return new BigInteger[] {e,n};
    }
    
    public BigInteger[] getPrimes(){
        return new BigInteger[] {prime1, prime2};
    }
    
    public BigInteger[] getKeys(){
            return new BigInteger[] {d,e,n};
    }
}
    
