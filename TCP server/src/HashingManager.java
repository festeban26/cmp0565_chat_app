package com.company;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingManager {

    private String hashAlgorithm;
    private MessageDigest messageDigest;
    private Charset charset;

    public HashingManager(String hashAlgorithm, Charset charset){
        try{
            this.hashAlgorithm = hashAlgorithm;
            this.messageDigest = MessageDigest.getInstance(hashAlgorithm);
            this.charset = charset;
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "No Provider supports an implementation for the \""
                    + hashAlgorithm + "\" algorithm.";
            ExceptionManager.NoSuchAlgorithmException.throwError(errorMessage);
        }
    }

    public byte[] hash_asByteArray(String input){
        return this.messageDigest.digest(input.getBytes(charset));
    }

    public byte[] hash_asByteArray(byte[] input){ return this.messageDigest.digest(input); }


    public String hash_asString(String input){

        byte[] hash = hash_asByteArray(input);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }

    public String hash_asString(byte[] input){

        byte[] hash = hash_asByteArray(input);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
