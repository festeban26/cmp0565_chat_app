
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class RsaManager {

    private static String hashingAlgorithm = "SHA-256";
    private static Charset charset = StandardCharsets.UTF_8;

    /**
     * This functions signs a byte array(data). It works by first hashing the data and then signing the hash
     * @param data the data to be signed
     * @param privateKey  the private key used to sign the data
     * @return signature of the hashed data
     */
    public static byte[] getSignature(byte[] data, Key privateKey){
        HashingManager hashingManager = new HashingManager(RsaManager.hashingAlgorithm, RsaManager.charset);
        byte[] hash = hashingManager.hash_asByteArray(data);
        return RsaManager.encrypt(hash,  privateKey);
    }

    public static String getEncodedSignature(byte[] data, Key privateKey){
        byte[] signature = RsaManager.getSignature(data, privateKey);
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean checkSignature(String data, String encodedSignature, Key publicKey){
        byte[] signature = Base64.getDecoder().decode(encodedSignature.getBytes());
        return RsaManager.checkSignature(data.getBytes(), signature, publicKey);
    }

    /**
     * Checks a signature of some data.
     * @param data the data that was signed
     * @param signature the signature
     * @param publicKey the public key used to verify the signature
     * @return the result of the boolean test
     */
    public static boolean checkSignature(byte[] data, byte[] signature, Key publicKey){

        HashingManager hashingManager = new HashingManager(RsaManager.hashingAlgorithm, RsaManager.charset);
        byte[] hashedData = hashingManager.hash_asByteArray(data);
        byte[] verifySignature = RsaManager.decrypt(signature, publicKey);

        if(Arrays.equals(hashedData, verifySignature))
            return true;
        return false;
    }

    public static byte[] encrypt(byte[] data, Key key){
        try{
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e){
            if(e instanceof InvalidKeyException){
                String errorMessage = "The given key is inappropriate for initializing the cipher.";
                ExceptionManager.InvalidKeyException.throwError(errorMessage);
            } else if (e instanceof  IllegalBlockSizeException){
                String errorMessage = "IllegalBlockSizeException.";
                ExceptionManager.IllegalBlockSizeException.throwError(errorMessage);
            }
            // Since RSA is a valid cipher transformation, this exception will not happen.
            else if (e instanceof  NoSuchAlgorithmException){}
            // Since RSA contains a padding scheme that is available, this exception will not happen.
            else if (e instanceof NoSuchPaddingException ){}
            // Since the cipher is in encryption mode, this exception will not happen.
            else if (e instanceof BadPaddingException){}
            // Any other error
            else { ExceptionManager.Error.throwError("Fatal error."); }
        }
        return null; // Unreachable code since ExceptionManager exits the program.
    }

    public static byte[] decrypt(byte[] data, Key key){
        try{
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e){
            if(e instanceof InvalidKeyException){
                String errorMessage = "The given key is inappropriate for initializing the cipher.";
                ExceptionManager.InvalidKeyException.throwError(errorMessage);
            } else if (e instanceof  IllegalBlockSizeException){
                String errorMessage = "IllegalBlockSizeException.";
                ExceptionManager.IllegalBlockSizeException.throwError(errorMessage);
            } else if (e instanceof BadPaddingException){
                String errorMessage = "The decrypted data is not bounded by the appropriate padding byte.";
                ExceptionManager.NoSuchPaddingException.throwError(errorMessage);
            }
            // Since RSA is a valid cipher transformation, this exception will not happen.
            else if (e instanceof  NoSuchAlgorithmException){}
            // Since RSA contains a padding scheme that is available, this exception will not happen.
            else if (e instanceof NoSuchPaddingException){}
            // Any other error
            else { ExceptionManager.Error.throwError("Fatal error."); }
        }
        return null; // Unreachable code since ExceptionManager exits the program.
    }

    private static void saveKeyToFile(String filename, BigInteger mod, BigInteger exp){

        File keyFile = new File(filename);
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(
                    new BufferedOutputStream(new FileOutputStream(keyFile)));
            objectOutputStream.writeObject(mod);
            objectOutputStream.writeObject(exp);
            objectOutputStream.close();
        } catch (IOException e) {
            String errorMessage = "RSA manager could not save the key \"" + filename + "\".";
            ExceptionManager.IOException.throwError(errorMessage);
        }
    }

    public static void saveKeyPairToFile(KeyPair keyPair){

        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            /* We use RSAPublicKeySpec and RSAPrivateKeySpec because they contain transparent
            methods for pulling out the parameters that make up a RSA key.*/
            RSAPublicKeySpec publicKey = keyFactory.getKeySpec(keyPair.getPublic(),
                    RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKey = keyFactory.getKeySpec(keyPair.getPrivate(),
                    RSAPrivateKeySpec.class);
            RsaManager.saveKeyToFile("PublicKey.key", publicKey.getModulus(), publicKey.getPublicExponent());
            RsaManager.saveKeyToFile("PrivateKey.key", privateKey.getModulus(), privateKey.getPrivateExponent());

        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "RSA manager could not generate a key pair. " +
                    "No Provider supports a KeyFactorySpi implementation for RSA algorithm.\".";
            ExceptionManager.BadFormatting.throwError(errorMessage);
        } catch (InvalidKeySpecException e) {
            String errorMessage = "The requested key specification is inappropriate for the given key, " +
                    "or the given key cannot be processed.";
            ExceptionManager.InvalidKeySpecException.throwError(errorMessage);
        }
    }

    public static String getEncodedKey(KeyPair keyPair, boolean isPublic){
        if(isPublic){
            PublicKey publicKey = keyPair.getPublic();
            return Base64.getEncoder().encodeToString(publicKey.getEncoded());
        }else{
            PrivateKey privateKey = keyPair.getPrivate();
            return Base64.getEncoder().encodeToString(privateKey.getEncoded());
        }
    }

    public static PublicKey getDecodedPublicKey(String encodedPublicKey){
        return RsaManager.getDecodedPublicKey(encodedPublicKey.getBytes());
    }

    public static PublicKey getDecodedPublicKey(byte[] encodedPublicKey){
        try{
            byte[] decodedPublicKey = Base64.getDecoder().decode(encodedPublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static PrivateKey getDecodedPrivateKey(byte[] encodedPrivateKey){
        try{
            byte[] decodedPrivateKey = Base64.getDecoder().decode(encodedPrivateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair getAKeyPair(int KEY_LENGTH){
        try{
            // Create an instance of KeyPairGenerator suitable for generating RSA keys.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            // Initialise the generator, telling it the bit length of the modulus that we require.
            keyPairGenerator.initialize(KEY_LENGTH);

            // Call genKeyPair(), which eventually returns a KeyPair object.
            KeyPair keyPair = keyPairGenerator.genKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "RSA manager could not generate a key pair. " +
                    "No Provider supports a KeyFactorySpi implementation for RSA algorithm.\".";
            ExceptionManager.BadFormatting.throwError(errorMessage);
        }
        return null; // Unreachable code since ExceptionManager exits the program.
    }

    /**
     * Function to read a RSA key (mod and exponent) from a file.
     *
     * @param keyPath The file path of the RSA key.
     */
    public static Key getKeyFromFile(String keyPath, boolean isKeyPublic) {

        if (FileManager.doesFileExist(keyPath)) {
            Path path = FileManager.getPathOfFile(keyPath);

            try {
                ObjectInputStream objectInputStream
                        = new ObjectInputStream(
                        new BufferedInputStream(
                                new FileInputStream(path.toFile())));

                // Pull out the two BigIntegers from the key file.
                BigInteger mod = (BigInteger) objectInputStream.readObject();
                BigInteger exp = (BigInteger) objectInputStream.readObject();

                // Use a KeyFactory instance to generate a corresponding Key object
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                Key key = null;
                if (isKeyPublic) {
                    // Wrap an RSAPublicKeySpec object around the two BigIntegers
                    RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(mod, exp);
                    key = keyFactory.generatePublic(rsaPublicKeySpec);
                } else {
                    // Wrap an RSAPublicKeySpec object around the two BigIntegers
                    RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(mod, exp);
                    key = keyFactory.generatePrivate(rsaPrivateKeySpec);
                }
                return key;

            } catch (IOException e) {
                String errorMessage = "IO Exception.";
                ExceptionManager.IOException.throwError(errorMessage);
            } catch (ClassNotFoundException e) {
                String errorMessage = "RSA manager could not load the key " +
                        "due to bad formatting on the key file.";
                ExceptionManager.BadFormatting.throwError(errorMessage);
            } catch (NoSuchAlgorithmException e) {
                String errorMessage = "RSA manager could not work properly. " +
                        "No Provider supports a KeyFactorySpi implementation for RSA algorithm.";
                ExceptionManager.NoSuchAlgorithmException.throwError(errorMessage);
            } catch (InvalidKeySpecException e) {
                String errorMessage = "The requested key specification is " +
                        "inappropriate for the given key, or the given key cannot be processed.";
                ExceptionManager.InvalidKeySpecException.throwError(errorMessage);
            }
        }
        // If the key could not be loaded, the program cannot continue its execution.
        else {
            String errorMessage = "The key could not be loaded because " +
                    "the file \"" + keyPath + "\" could not be found.";
            ExceptionManager.FileNotFoundException.throwError(errorMessage);
        }
        return null; // Unreachable code since ExceptionManager exits the program.
    }
}
