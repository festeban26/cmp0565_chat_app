import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

/**
 * Bibliography:
 *  Java AES CBC encryption example: https://gist.github.com/itarato/abef95871756970a9dad
 */

public class AesManager {

    // This class manages the AES-CBC algorithm
    private static final String CIPHER_TRANSFORMATION_NAME = "AES/CBC/PKCS5Padding";
    // AES/CBC/PKCS5Padding requieres a 16 IV size
    private static final int IV_SIZE = 16;

    public static String generateEncodedSecretKey(int keyLength){
        return Base64.getEncoder().encodeToString(AesManager.generateSecretKey(keyLength).getEncoded());
    }

    public static String getEncodedSecretKey(SecretKey secretKey){
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static SecretKey getDecodedKey(String encodedKey){
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }


    public static SecretKey generateSecretKey(int keyLength){
        try{
            // Key generator to be used with AES algorithm.
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            // Set key size.
            keyGenerator.init(keyLength);
            // Return an AES key
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = "AES manager could not generate a key. " +
                    "No Provider supports a KeyFactorySpi implementation for AES algorithm.\".";
            ExceptionManager.NoSuchAlgorithmException.throwError(errorMessage);
        }
        return null; // Unreachable code since ExceptionManager exits the program.
    }

    public static byte[] encrypt(byte[] data, Key key){

        try{
            // Generate IV
            byte[] iv = new byte[AesManager.IV_SIZE];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Sets the cipher
            // Create a cipher instance that will encrypt the data.
            Cipher cipher = Cipher.getInstance(AesManager.CIPHER_TRANSFORMATION_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

            // Encrypt data
            byte [] encryptedData = cipher.doFinal(Base64.getEncoder().encode(data));

            // Combine IV and encrypted data
            byte[] encryptedIVAndData = new byte[AesManager.IV_SIZE + encryptedData.length];
            System.arraycopy(iv, 0, encryptedIVAndData, 0, AesManager.IV_SIZE);
            System.arraycopy(encryptedData, 0, encryptedIVAndData, AesManager.IV_SIZE, encryptedData.length);
            return encryptedIVAndData;
        }

        catch (NoSuchPaddingException e) {
            String errorMessage = "Padding exception.";
            ExceptionManager.NoSuchPaddingException.throwError(errorMessage);
        }
        catch (NoSuchAlgorithmException e) {
            String errorMessage = "No Provider supports a KeyFactorySpi implementation for the "
                    + AesManager.CIPHER_TRANSFORMATION_NAME + "algorithm.\".";
            ExceptionManager.NoSuchAlgorithmException.throwError(errorMessage);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            String errorMessage = "Could not initialize the cipher.";
            ExceptionManager.InvalidAlgorithmParameterException.throwError(errorMessage);
        } catch (InvalidKeyException e) {
            String errorMessage = "Could not initialize the cipher.";
            ExceptionManager.InvalidKeyException.throwError(errorMessage);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(byte[] data, Key key){
        try{
            // Extract IV
            byte[] iv = new byte[AesManager.IV_SIZE];
            System.arraycopy(data, 0, iv, 0, iv.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Extract encrypted part
            int encryptedSize = data.length - AesManager.IV_SIZE;
            byte[] encryptedBytes = new byte[encryptedSize];
            System.arraycopy(data, AesManager.IV_SIZE, encryptedBytes, 0, encryptedSize);

            // Decrypt
            Cipher cipher = Cipher.getInstance(AesManager.CIPHER_TRANSFORMATION_NAME);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return Base64.getDecoder().decode(cipher.doFinal(encryptedBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;

    }
}
