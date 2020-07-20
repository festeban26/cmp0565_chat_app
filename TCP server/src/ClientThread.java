package com.company;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Random;

public class ClientThread extends Thread implements Serializable{

    private static String HASHING_ALGORITHM;
    private static Charset CHARSET;
    private static String SPLIT_CHARS = "ßż";
    // Keys must be located on the same directory
    private static String SERVER_PRIVATE_KEY_FILENAME = "PrivateKey.key";
    private static String USERS_VAULT_FILENAME = "ChatAppUserCredentialsVault.json";
    private static int POW_DIFFICULTY = 16;

    private String username = null;
    private Socket clientSocket = null;
    private SecretKey symmetricKey;
    private PublicKey publicKey;

    private int portListenClient;

    private DataInputStream dataInputStream = null;
    private DataOutputStream sendData = null;

    private final ClientThread[] threads;
    private int maxClientsCount;

    public ClientThread(Socket clientSocket, ClientThread[] threads,
                        String HASHING_ALGORITHM, Charset CHARSET) {
        this.clientSocket = clientSocket;
        this.threads = threads;
        this.HASHING_ALGORITHM = HASHING_ALGORITHM;
        this.CHARSET = CHARSET;
        maxClientsCount = threads.length;
    }

    public void run() {

        int bits;
        int nonce;
        int read;
        String complete;
        byte[] tempArr;
        String[] decomposeCommand = null;
        int maxClientsCount = this.maxClientsCount;
        ClientThread[] threads = this.threads;

        try {
            //Create input and output streams for this client.
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            sendData = new DataOutputStream(clientSocket.getOutputStream());

            if(login()){
                sendUsersConnectedBefore();
                userListUpdateClients();
                //String d = "Welcome to the chat";
                //sendMessage(d);

                System.out.println("CONNECTED USERS");
                for(int i=0;i<10;i++)
                    if(threads[i] != null)
                        System.out.println(threads[i].getUsername() + " port: " + threads[i].getClientSocket().getPort());

                // Start the conversation.
                while (true) {
                    read = dataInputStream.readInt();
                    complete = new String(receiveMessage(read));

                    if(complete.contains(this.SPLIT_CHARS))
                    {
                        decomposeCommand = complete.split(this.SPLIT_CHARS);
                        complete = decomposeCommand[0];
                    }else {
                        tempArr = Base64.getDecoder().decode(complete.getBytes());
                        tempArr = AesManager.decrypt(tempArr, this.symmetricKey);
                        complete = new String(tempArr);
                        System.out.println(complete);
                    }



                    switch(complete){
                        case "logout":
                            bits = ClientThread.POW_DIFFICULTY;
                            Random rand = new Random(System.currentTimeMillis());
                            nonce = rand.nextInt(Integer.MAX_VALUE);
                            StringBuilder sb = new StringBuilder("logout" + this.SPLIT_CHARS + bits + this.SPLIT_CHARS + nonce);
                            tempArr = String.valueOf(sb).getBytes();
                            tempArr = Base64.getEncoder().encode
                                    (AesManager.encrypt(tempArr, this.symmetricKey));
                            sendMessage(new String(tempArr));
                            break;

                        case "logoutTest":

                            int solution = Integer.parseInt(decomposeCommand[1]);
                            int tempNonce = Integer.parseInt(decomposeCommand[2]);

                            PowManager powManager = new PowManager(ClientThread.HASHING_ALGORITHM, ClientThread.CHARSET);
                            // If the client passed the POW

                            System.out.println("LOGOUT TEST");
                            if(powManager.checkPow(ClientThread.POW_DIFFICULTY, solution, tempNonce)) {
                                sb = new StringBuilder("exit" + this.SPLIT_CHARS + 0);
                                tempArr = String.valueOf(sb).getBytes();
                                tempArr = Base64.getEncoder().encode
                                        (AesManager.encrypt(tempArr, this.symmetricKey));
                                sendMessage(new String(tempArr));
                            }
                            break;
                        case "wanna_talk":
                            helpConversation();
                            break;
                    }
                }
            }
            else{
                dataInputStream.close();
                sendData.close();
                return;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Socket getClientSocket() {
        return clientSocket;
    }

    public void setClientSocket(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    public int getPortListenClient() {
        return portListenClient;
    }

    public void setPortListenClient(int portListenClient) {
        this.portListenClient = portListenClient;
    }

    public boolean login(){

        System.out.println("LOGIN SEQUENCE");
        try {
            int read;
            StringBuilder sb; // Temp String Builder
            byte[] tempArr;
            String SEPARATOR = ClientThread.SPLIT_CHARS;

            // LOGIN STEP 2
            int bits = ClientThread.POW_DIFFICULTY;
            Random rand = new Random(System.currentTimeMillis());
            int nonce = rand.nextInt(Integer.MAX_VALUE);
            sb = new StringBuilder(bits + SEPARATOR + nonce);
            sendMessage(String.valueOf(sb));

            // LOGIN STEP 3
            read = dataInputStream.readInt();
            byte[] receivedData = Base64.getDecoder().decode(receiveMessage(read));
            String[] components = new String(receivedData).split(SEPARATOR);

            if(components.length == 4){
                // First, check POW solution
                int clientPowSolution = Integer.valueOf(components[1]);
                PowManager powManager = new PowManager(ClientThread.HASHING_ALGORITHM, ClientThread.CHARSET);
                // If the client passed the POW
                if(powManager.checkPow(bits, clientPowSolution, nonce)) {
                    int port = Integer.valueOf(components[0]);
                    // BLOCK 3
                    tempArr = Base64.getDecoder().decode(components[2].getBytes());
                    Key serverPrivateKey = RsaManager.getKeyFromFile
                            (ClientThread.SERVER_PRIVATE_KEY_FILENAME, false);
                    byte[] decryptedBlock3 = RsaManager.decrypt(tempArr, serverPrivateKey);
                    String[] block3Components = new String(decryptedBlock3).split(SEPARATOR);

                    if(block3Components.length == 3){
                        String symmetricKey_asString = block3Components[0];
                        String encodedPassword = block3Components[1];
                        String username = block3Components[2];

                        // First, validate the user.
                        PasswordVaultManager passwordVaultManager = new PasswordVaultManager(
                                ClientThread.USERS_VAULT_FILENAME, ClientThread.HASHING_ALGORITHM, ClientThread.CHARSET);

                        // If the user is validated (Correct username and password)
                        if (passwordVaultManager.authenticate(username, encodedPassword)) {
                            this.symmetricKey = AesManager.getDecodedKey(symmetricKey_asString);
                            tempArr = Base64.getDecoder().decode(components[3].getBytes());
                            byte[] decryptedBlock4 = AesManager.decrypt(tempArr, this.symmetricKey);
                            String[] block4Components = new String(decryptedBlock4).split(SEPARATOR);
                            String clientPublicKey_asString = block4Components[0];
                            String nonceC2_asString = block4Components[1];
                            String signatureOfNonceC2_asString = block4Components[2];
                            // Save the client Public Key
                            this.publicKey = RsaManager.getDecodedPublicKey(clientPublicKey_asString);

                            // If the sender signature of C2 is the valid signature of C2
                            // (Authentication of packet sent by Alice)
                            if (RsaManager.checkSignature
                                    (nonceC2_asString, signatureOfNonceC2_asString, this.publicKey)){
                                System.out.println("User authenticated");
                                userListAdd(username, port);

                                // LOGIN STEP 4
                                // sign  nounce C2
                                String serverSignatureOfC2 = RsaManager.getEncodedSignature(
                                        nonceC2_asString.getBytes(), serverPrivateKey);

                                sb = new StringBuilder();
                                sb.append(serverSignatureOfC2);
                                tempArr = String.valueOf(sb).getBytes();
                                tempArr = Base64.getEncoder()
                                        .encode(AesManager.encrypt(tempArr, this.symmetricKey));
                                sendMessage(new String(tempArr));
                                return true;

                            }
                        }
                    }
                }
            }
            loginError();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void loginError(){
        byte[] tempArr = "LOGINERROR".getBytes();
        tempArr = Base64.getEncoder().encode(tempArr);
        StringBuilder sb = new StringBuilder();
        sb.append(new String(tempArr));
        sendMessage(String.valueOf(sb));
    }

    public void sendMessage(String data){

        byte[] message;
        message = data.getBytes();
        try {
            sendData.writeInt(message.length);
            sendData.write(message);
        } catch (IOException e) { e.printStackTrace(); }
    }

    public byte[] receiveMessage(int size){

        byte[] complete = new byte[size];

        try{
            dataInputStream.readFully(complete, 0, size);
        } catch (IOException e) { e.printStackTrace(); }
        return complete;
    }

    public void userListAdd(String user, int port){

        synchronized (this) {
            //Add to server's list of users
            for (int i = 0; i < maxClientsCount; i++) {
                if (threads[i] != null && threads[i] == this) {
                    this.setUsername(user);
                    this.setPortListenClient(port);
                    break;
                }
            }
            //Send the update alert to all the active clients
        }
    }

    //update other clients about my connection
    public void userListUpdateClients(){
        String SEPARATOR = ClientThread.SPLIT_CHARS;
        synchronized (this) {
            StringBuilder update = new StringBuilder
                    ("updateUser" + SEPARATOR + this.getUsername() + SEPARATOR
                            + this.getClientSocket().getPort() +  SEPARATOR + "1");
            String newUser = String.valueOf(update);
            byte[] tempArr;
            for (int j = 0; j < maxClientsCount; j++) {
                if (threads[j] != null) {
                    if(!threads[j].getUsername().equals(this.getUsername())) {
                        //tempArr = newUser.getBytes();
                        //tempArr = AesManager.encrypt(tempArr, this.symmetricKey);
                        //tempArr = Base64.getEncoder().encode(tempArr);
                        threads[j].sendMessage(newUser);
                    }
                }
            }
        }
    }

    //update my user list
    public void sendUsersConnectedBefore(){
        synchronized (this) {
            this.sendMessage("userList_start");
            byte[] tempArr;
            for (int j = 0; j < maxClientsCount; j++) {
                if (threads[j] != null && threads[j] != this) {
                    StringBuilder update = new StringBuilder
                            (threads[j].getUsername() + ClientThread.SPLIT_CHARS + threads[j].getClientSocket().getPort() + ClientThread.SPLIT_CHARS +"1");
                    String newUser = String.valueOf(update);
                    if(!threads[j].getUsername().equals(this.getUsername())){
                        tempArr = newUser.getBytes();
                        tempArr = Base64.getEncoder().encode
                                (AesManager.encrypt(tempArr, this.symmetricKey));
                        this.sendMessage(new String(tempArr));
                    }
                }
            }
            tempArr = "userList_end".getBytes();
            tempArr = Base64.getEncoder().encode
                    (AesManager.encrypt(tempArr, this.symmetricKey));
            this.sendMessage(new String(tempArr));
        }
    }

    public void helpConversation(){
        int read;
        String request;
        int bits = ClientThread.POW_DIFFICULTY;
        String SEPARATOR = ClientThread.SPLIT_CHARS;
        byte[] tempArr;
        Random rand = new Random(System.currentTimeMillis());
        int nonceC1 = rand.nextInt(Integer.MAX_VALUE);
        SecretKey destinationUserSecretKey = null;

        int portClientToListen = 0;
        StringBuilder pow;
        try {

            pow = new StringBuilder("proofRobot" + ClientThread.SPLIT_CHARS
                    + bits + ClientThread.SPLIT_CHARS + nonceC1);
            sendMessage(String.valueOf(pow));


            // STEP3
            read = dataInputStream.readInt();
            tempArr = receiveMessage(read);
            tempArr = Base64.getDecoder().decode(tempArr);

            request = new String(tempArr);

            String[] data = request.split(SEPARATOR);
            PowManager powManager = new PowManager(ClientThread.HASHING_ALGORITHM, ClientThread.CHARSET);
            // Only continue if the POW have been passed
            if(powManager.checkPow(bits, Integer.parseInt(data[0]), nonceC1)){

                tempArr = Base64.getDecoder().decode(data[1].getBytes());
                tempArr = AesManager.decrypt(tempArr, this.symmetricKey);
                String step3Block2 = new String(tempArr);
                String components[] = step3Block2.split(SEPARATOR);
                String username = components[0];

                PublicKey destinationUserPublicKey;
                // Check if user exists
                boolean existUser = false;
                for (int i= 0 ;i<10; i++){
                    if(threads[i] != null) {
                        if(threads[i].getUsername().equalsIgnoreCase(username)){
                            existUser = true;
                            destinationUserPublicKey = threads[i].publicKey;
                            portClientToListen = threads[i].portListenClient;
                            destinationUserSecretKey = threads[i].symmetricKey;
                        }
                    }
                }

                if(existUser){

                    tempArr = Base64.getDecoder().decode(components[1].getBytes());
                    PublicKey clientDhPublicKey = DhManager.getDecodedPublicKey(tempArr);
                    String nonceC2 = components[2];
                    String clientSignatureOfNonceC1 = components[3];
                    // Validate signature of C1
                    if(RsaManager.checkSignature(String.valueOf(nonceC1), clientSignatureOfNonceC1, this.publicKey )){
                        Key serverPrivateKey = RsaManager.getKeyFromFile
                                (ClientThread.SERVER_PRIVATE_KEY_FILENAME, false);
                        String serverSignatureOfC2 = RsaManager.getEncodedSignature
                                (nonceC2.getBytes(), serverPrivateKey);


                        StringBuilder sb = new StringBuilder();
                        sb.append(this.username).append(SEPARATOR);

                        tempArr = this.publicKey.getEncoded();
                        tempArr = Base64.getEncoder().encode(tempArr);
                        sb.append(new String(tempArr)).append(SEPARATOR);

                        tempArr = clientDhPublicKey.getEncoded();
                        tempArr = Base64.getEncoder().encode(tempArr);
                        sb.append(new String(tempArr));

                        String ticket = String.valueOf(sb);

                        if(destinationUserSecretKey != null){
                            tempArr = AesManager.encrypt(ticket.getBytes(), destinationUserSecretKey);
                            tempArr = Base64.getEncoder().encode(tempArr);
                            ticket = new String(tempArr);

                            sb = new StringBuilder();
                            sb.append("ticket").append(SEPARATOR);


                            String destinationUserPort = String.valueOf(portClientToListen);
                            StringBuilder step4Block2Sb = new StringBuilder();
                            step4Block2Sb.append(destinationUserPort).append(SEPARATOR);
                            step4Block2Sb.append(serverSignatureOfC2);
                            String step4Block2 = String.valueOf(step4Block2Sb);

                            tempArr = AesManager.encrypt(step4Block2.getBytes(), this.symmetricKey);
                            tempArr = Base64.getEncoder().encode(tempArr);
                            sb.append(new String(tempArr)).append(SEPARATOR);
                            sb.append(ticket);
                            sendMessage(String.valueOf(sb));
                        }
                    }
                }
            }
        } catch (IOException e) { e.printStackTrace(); }
    }
}
