package com.company;

import java.nio.charset.Charset;
import java.util.ArrayList;

public class PasswordVaultManager {
    // Las claves se guardan en formato Json de forma de tuplas, asi: hash(username), hash(username, password)

    private String vaultFileName;
    private String vaultHashAlgorithm;
    private Charset vaultCharset;

    public PasswordVaultManager(String vaultFileName,String vaultHashAlgorithm, Charset vaultCharset){

        this.vaultFileName = vaultFileName;
        this.vaultHashAlgorithm = vaultHashAlgorithm;
        this.vaultCharset = vaultCharset;
    }

    /**
     *
     * @param username plain text username
     * @param encodedPassword encoded password
     * @return
     */
    public boolean authenticate(String username, String encodedPassword){

        ArrayList<UserCredential> userCredentialsArrayList = new ArrayList<>();
        userCredentialsArrayList = JsonManager.readData(this.vaultFileName);

        HashingManager hashingManager = new HashingManager(this.vaultHashAlgorithm, this.vaultCharset);
        String hashedUsername = hashingManager.hash_asString(username);

        for (UserCredential userCredential : userCredentialsArrayList){

            String vaultUsername = userCredential.getUsername();
            String vaultPassword = userCredential.getPassword();

            boolean usernameMatch = vaultUsername.equalsIgnoreCase(hashedUsername);
            boolean passwordMatch = vaultPassword.equalsIgnoreCase(encodedPassword);
            if(usernameMatch && passwordMatch)
                return true;
        }
        return false;
    }
}
