package com.company;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class DhManager {

    private static int KEY_SIZE = 2048;

    public static KeyPair getAKeyPair(){
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(DhManager.KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        }
        // Since DH is a valid cipher transformation, this exception will not happen.
        catch (NoSuchAlgorithmException e) { }
        return null; // Unreachable code
    }

    public static KeyPair getAKeyPairFromAssociatedDhParametersOfPublicKey(PublicKey publicKey){
        try{
            DHParameterSpec dhParameterSpec = DhManager.getDhParametersSpec(publicKey);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(dhParameterSpec);
            return keyPairGenerator.generateKeyPair();
        }
        // Since DH is a valid cipher transformation, this exception will not happen.
        catch (NoSuchAlgorithmException e) { }
        catch (InvalidAlgorithmParameterException e) {
            // TODO
            e.printStackTrace();
        }
        return null; // Unreachable code
    }

    public static KeyAgreement getKeyAgreement(PrivateKey privateKey){
        try{
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            return keyAgreement;
        }
        // Since DH is a valid cipher transformation, this exception will not happen.
        catch (NoSuchAlgorithmException e) { }
        catch (InvalidKeyException e) {
            String errorMessage = "Error.";
            ExceptionManager.InvalidKeyException.throwError(errorMessage);
        }
        return null; // Unreachable code
    }

    public static byte[] getEncodedPublicKey(PublicKey publicKey){
        return publicKey.getEncoded();
    }


    public static PublicKey getDecodedPublicKey(byte[] encodedPublicKey){
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedPublicKey);
            return keyFactory.generatePublic(x509EncodedKeySpec);
        }
        // Since DH is a valid cipher transformation, this exception will not happen.
        catch (NoSuchAlgorithmException e) { }
        catch (InvalidKeySpecException e) {
            String errorMessage = "Error.";
            ExceptionManager.InvalidKeySpecException.throwError(errorMessage);
        }
        return null;  // Unreachable code
    }

    public static DHParameterSpec getDhParametersSpec(PublicKey publicKey){
        return ((DHPublicKey)publicKey).getParams();
    }

}
