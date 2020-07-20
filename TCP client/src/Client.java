
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Random;

import static java.lang.Thread.sleep;

public class Client implements Runnable, Serializable{

    private static String HASHING_ALGORITHM = "SHA-256";
    private static Charset CHARSET = StandardCharsets.UTF_8;
    public static String SPLIT_CHAR = "ßż";
    private static String SERVER_KEY_FILENAME = "ServerPublicKey.key";
    private static int AES_KEY_SIZE = 128;
    private static int RSA_KEY_SIZE = 2048;

    private static PrivateKey privateKey; // RSA Private Key
    public static SecretKey symmetricKey; // AES Secret Key
    private static KeyPair dhKeyPair;

    private static Socket client = null;
    private static boolean login = false;
    private static BufferedReader inputLine = null;
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;
    public static final User[] availableUsers = new User[9];


    public static String nameUserToSend;
    public static String messageUserToSend;

    public static int portUserToSend;
    public static boolean checkProofRobot;

    public static String messageTestRobot;

    public static boolean checkTicket;

    public static String messageTicket;
    //objecto to read connections from other clients
    public static User listenerUser;

    public static String myUsername;

    public static ClientManager ReadListenerThread;

    public static void main(String[] args) {

        Random rand = new Random();
        int myListeningPortClient = rand.nextInt(3000) + 1;
        int size;
        String temporal;
        String options;
        String sendTo;
        byte[] tempArr;
        //Server Data
        String host = "localhost";
        int serverPortNumber = 2222;
        connectToSocket( host, serverPortNumber);
        int localPort = client.getLocalPort();
        System.out.println("Connection to Server: " + host + ", portNumber: " + serverPortNumber);
        System.out.println("From IP: " + host  + " listeningPortClient " + myListeningPortClient);
        try {
            //first message response from server
            size = dataInputStream.readInt();
            temporal = receiveMessage(size);
            loginSequence(temporal, myListeningPortClient);
            //USERLIST
            size = dataInputStream.readInt();
            temporal = receiveMessage(size);
            if(temporal.equals("userList_start"))
            {
                size = dataInputStream.readInt();
                temporal = receiveMessage(size);
                tempArr = Base64.getDecoder().decode(temporal.getBytes());
                tempArr = AesManager.decrypt(tempArr, Client.symmetricKey);
                temporal = new String(tempArr);
                while(!temporal.equals("userList_end"))
                {
                    userAddRemove(temporal);
                    size = dataInputStream.readInt();
                    temporal = receiveMessage(size);
                    tempArr = Base64.getDecoder().decode(temporal.getBytes());
                    tempArr = AesManager.decrypt(tempArr, Client.symmetricKey);
                    temporal = new String(tempArr);
                }
            }
            System.out.println("Success login");
        } catch (IOException e) {
            System.err.println("IOException:  " + e);
        }

        listenerUser = new User(myUsername, myListeningPortClient);
        listenerUser.start();

        if (client != null && dataInputStream != null ) {
            System.out.println("CLIENT");

            new Thread(new Client()).start();
        }

        while(login){
            System.out.println("MENU");
            System.out.println("quit: exit program");
            System.out.println("list: users available");
            System.out.println("send USER MESSAGE: send message to user");
            try {
                options = inputLine.readLine();
                options = validateChatCommand(options);

                switch (options) {
                    case "quit":

                        tempArr = "logout".getBytes();
                        tempArr = Base64.getEncoder().encode
                                (AesManager.encrypt(tempArr, Client.symmetricKey));
                        sendMessage(new String(tempArr));
                        //TODO. Close conections
                        //dataInputStream.close();
                        //dataOutputStream.close();
                        //System.out.println("Program closing");
                        //System.exit(0);
                    case "list":
                        printOnlineUsers();
                        break;
                    case "send":
                        if (checkExistUser(nameUserToSend)) {
                            if(!checkExistTicket(nameUserToSend)) {
                                requestClientInformation(nameUserToSend);
                                //openConnectionClient();
                            } else {
                                sendMessageToClient(nameUserToSend,messageUserToSend);
                            }
                            System.out.println("Si existe");
                        }
                        break;
                    default:
                        System.out.println("Command not valid");
                        break;
                }
            } catch (IOException e) {
                System.out.println("...closing sockets");
            }
        }
    }

    //Thread to read from server
    public void run() {

        int size;
        String message;
        String data[];
        String commandFromServer;
        String SEPARATOR  = Client.SPLIT_CHAR;
        byte[] tempArr;
        try{
           while(true) {
                size = dataInputStream.readInt();
                if(size !=0) {
                    message = receiveMessage(size);
                    if(message.contains("updateUser") || message.contains("proofRobot") || message.contains("ticket")){
                        data = message.split(SEPARATOR);
                        commandFromServer = data[0];
                    } else {
                        tempArr = Base64.getDecoder().decode(message.getBytes());
                        tempArr = AesManager.decrypt(tempArr, this.symmetricKey);
                        message = new String(tempArr);

                        data = message.split(SEPARATOR);
                        commandFromServer = data[0];
                        //System.out.println(commandFromServer);
                    }
                    System.out.println(commandFromServer);
                    switch( commandFromServer)
                    {
                        case "updateUser":
                            System.out.println("UPDATING USER");
                            message = message.replace(commandFromServer + SEPARATOR,"");
                            userAddRemove(message);
                            break;
                        case "proofRobot":
                            //alerts main about a ewanna talk
                            checkProofRobot = true;
                            messageTestRobot = message;
                            break;
                        case "ticket":
                            checkTicket = true;
                            //test to pas s for ticket proces
                            messageTicket = message;
                            break;
                        case "logout":
                            int bits = Integer.parseInt(data[1]);
                            int nonce = Integer.parseInt(data[2]);
                            PowManager proofOfWorkManager = new PowManager(Client.HASHING_ALGORITHM, Client.CHARSET);
                            int result = proofOfWorkManager.doPow(bits,nonce);
                            StringBuilder sb = new StringBuilder("logoutTest" + SEPARATOR + result + SEPARATOR + nonce);
                            tempArr = String.valueOf(sb).getBytes();
                            tempArr = Base64.getEncoder().encode
                                    (AesManager.encrypt(tempArr, Client.symmetricKey));
                            sendMessage(new String(tempArr));

                            break;
                        case "exit":

                            System.out.println("Succesfull logout");
                            if(Integer.valueOf(data[1]) == 0)
                                System.out.println("Succesfull logout");
                            break;
                        default:
                            break;
                    }
                }
            }


        } catch (IOException e) {
            System.err.println("IOException:  " + e);
        }
    }

    //steps to verify the client with the server
    public static void loginSequence(String data, int listeningPortClient){

        String username;
        String plaintTextPassword;
        StringBuilder dataToSend = new StringBuilder();
        StringBuilder sb; // Temp String Builder
        byte[] tempArr; // Temp byte array
        String SEPARATOR = Client.SPLIT_CHAR;
        // LOGIN STEP 2
        String[] pow = data.split(SEPARATOR);
        int bits = Integer.parseInt(pow[0]);
        int nonce = Integer.parseInt(pow[1]);
        PowManager proofOfWorkManager = new PowManager(Client.HASHING_ALGORITHM, Client.CHARSET);
        int powResult = proofOfWorkManager.doPow(bits,nonce);
        // Append listening port(BLOCK 1) + pow solution (BLOCK 2)
        dataToSend.append(listeningPortClient).append(SEPARATOR).append(powResult).append(SEPARATOR);

        // LOGIN STEP 3
        try {
            System.out.println("LOGIN");
            System.out.print("USERNAME: ");
            username = inputLine.readLine();
            myUsername = username;
            System.out.print("PASSWORD: ");
            plaintTextPassword = inputLine.readLine();

            // Encode password: hash(planTextPassword, username)
            HashingManager hashingManager = new HashingManager(Client.HASHING_ALGORITHM, Client.CHARSET);
            String encodedPassword = hashingManager.hash_asString(plaintTextPassword + username);

            // Get a encoded symmetric key
            SecretKey symmetricKey = AesManager.generateSecretKey(Client.AES_KEY_SIZE);
            Client.symmetricKey = symmetricKey;
            String symmetricKey_asString = AesManager.getEncodedSecretKey(symmetricKey);
            // plain text BLOCK 3
            sb = new StringBuilder(symmetricKey_asString + SEPARATOR + encodedPassword + SEPARATOR + username);
            // Get server Public Key
            Key serverPublicKey = RsaManager.getKeyFromFile(Client.SERVER_KEY_FILENAME, true);
            tempArr = String.valueOf(sb).getBytes();
            tempArr = Base64.getEncoder().encode(RsaManager.encrypt(tempArr, serverPublicKey));
            // Append BLOCK 3
            dataToSend.append(new String(tempArr)).append(SEPARATOR);

            // BLOCK 4
            // Generate an RSA key pair on runtime
            KeyPair clientRsaKeyPair = RsaManager.getAKeyPair(Client.RSA_KEY_SIZE);
            // Save the client Public, Private keys for this client application instance
            Client.privateKey = clientRsaKeyPair.getPrivate();

            sb = new StringBuilder();
            // Append client public key
            sb.append(RsaManager.getEncodedKey(clientRsaKeyPair, true)).append(SEPARATOR);
            // Create nonceC2
            Random rand = new Random(System.currentTimeMillis());
            int nonceC2 = rand.nextInt(Integer.MAX_VALUE);
            String nonceC2_asString = String.valueOf(nonceC2);
            sb.append(nonceC2_asString).append(SEPARATOR);
            String signatureOfNonceC2 = RsaManager.getEncodedSignature(
                    nonceC2_asString.getBytes(), Client.privateKey);
            sb.append(signatureOfNonceC2);

            // Encrypt block 4
            tempArr = String.valueOf(sb).getBytes();
            tempArr = Base64.getEncoder().encode(AesManager.encrypt(tempArr, Client.symmetricKey));
            // Append BLOCK 4
            dataToSend.append(new String(tempArr));

            // Format and send Data
            byte[] formattedData = Base64.getEncoder().encode( String.valueOf(dataToSend).getBytes());
            sendMessage(formattedData);


            // LOGIN STEP 4
            int readSize = dataInputStream.readInt();
            byte[] receivedData = Base64.getDecoder().decode(receiveMessage(readSize));


            if(new String(receivedData).equalsIgnoreCase("LOGINERROR")){
                System.out.println("Incorrect username or password. Application closing...");
                System.exit(0);
            } else{
                byte[] decryptedStep4Block = AesManager.decrypt(receivedData, Client.symmetricKey);
                String[] step4Block = new String(decryptedStep4Block).split(SEPARATOR);
                String serverSignatureOfNonceC2 = step4Block[0];
                // Authenticate the server before anything else
                if(RsaManager.checkSignature(nonceC2_asString, serverSignatureOfNonceC2, serverPublicKey)){
                    login = true;
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * @param ip
     * @param port
     * connect to an specific socket and port
     */
    public static void connectToSocket(String ip, int port){
        try {
            client = new Socket(ip, port);
            inputLine = new BufferedReader(new InputStreamReader(System.in));
            dataInputStream = new DataInputStream(client.getInputStream());
            dataOutputStream = new DataOutputStream(client.getOutputStream());
        } catch (IOException e) {
            System.err.println("IOException:  " + e);
        }
    }

    public static void sendMessage(byte[] data){
        try {
            dataOutputStream.writeInt(data.length);
            dataOutputStream.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sendMessage(String data){

        byte[] message;
        message = data.getBytes();

        try {

            dataOutputStream.writeInt(message.length);
            dataOutputStream.write(message);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String receiveMessage(int size){

        String result;
        byte[] complete = new byte[size];

        try{
            dataInputStream.readFully(complete, 0, size);
        } catch (IOException e) {
            e.printStackTrace();
        }
        result = new String(complete);
        return result;
    }

    public static String validateChatCommand(String inputLine){
        nameUserToSend =null;
        messageUserToSend =null;
        String command;


        if(inputLine.length() == 0) {
            return null;
        }

        //check if it is quit or list command
        String[] destroyedMessage = inputLine.split(" ");
        command = destroyedMessage[0];
        if(String.valueOf(destroyedMessage[0]).equals("send")) {
            String user = String.valueOf(destroyedMessage[1]);
            if (user.length() != 0) {

                nameUserToSend = destroyedMessage[1];
                inputLine = inputLine.replace(command,"");
                messageUserToSend = inputLine.replace(nameUserToSend,"");
                return command;
            }
        }

        return command;
    }

    public static boolean checkExistUser(String toUser){

        for (int i=0; i<availableUsers.length;i++)
        {
            if(availableUsers[i].getUser().equals(toUser)){
                return true;
            } else{

                System.out.println("User does not exist");
                System.out.println("Wrong structure please follow the example");
                return false;
            }
        }
        return false;
    }

    public static boolean checkExistTicket(String toUser){

        for (int i=0; i<availableUsers.length;i++)
        {
            if(availableUsers[i].getUser().equals(toUser)){
                if(availableUsers[i].isTicket()) {
                    return true;
                } else {
                    return false;
                }
            }
        }
        return false;
    }

    ///request data to connect to bob
    public static void requestClientInformation(String user){

        int read;
        String request;
        String SEPARATOR = Client.SPLIT_CHAR;
        checkProofRobot = false;
        checkTicket = false;
        String wantToTalk = "wanna_talk"+ Client.SPLIT_CHAR + 0;
        sendMessage(wantToTalk);
        while(true && checkProofRobot==false){
            try {
                sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        String[] pow = messageTestRobot.split(Client.SPLIT_CHAR);
        int bits = Integer.parseInt(pow[1]);
        int nonceC1 = Integer.parseInt(pow[2]);
        PowManager proofOfWorkManager = new PowManager(Client.HASHING_ALGORITHM, Client.CHARSET);
        String powResult = String.valueOf(proofOfWorkManager.doPow(bits,nonceC1));

        StringBuilder sb = new StringBuilder();
        byte[] tempArr;

        // STEP 3
        // Append SOL
        sb.append(powResult).append(SEPARATOR);
        StringBuilder step3Block2 = new StringBuilder();
        // APPEND username
        step3Block2.append(user).append(SEPARATOR);
        Client.dhKeyPair = DhManager.getAKeyPair();
        byte[] clientPublicKey = DhManager.getEncodedPublicKey(Client.dhKeyPair.getPublic());
        String clientPublicKey_asString =
                new String(Base64.getEncoder().encode(clientPublicKey));
        // Append DH_A
        step3Block2.append(new String(clientPublicKey_asString)).append(SEPARATOR);
        // Generate C2
        Random rand = new Random(System.currentTimeMillis());
        int nonceC2 = rand.nextInt(Integer.MAX_VALUE);
        // Append C2
        step3Block2.append(String.valueOf(nonceC2)).append(SEPARATOR);
        String nonceC1_asString = String.valueOf(nonceC1);
        String c1Signature = RsaManager.getEncodedSignature(nonceC1_asString.getBytes(), Client.privateKey);
        // Append C1 signature
        step3Block2.append(c1Signature);
        tempArr = String.valueOf(step3Block2).getBytes();
        tempArr = AesManager.encrypt(tempArr, Client.symmetricKey);
        tempArr = Base64.getEncoder().encode(tempArr);
        String step3Block2_asString = new String(tempArr);
        // Append BLOCK 2
        sb.append(step3Block2_asString);

        sendMessage(new String(Base64.getEncoder().encode(String.valueOf(sb).getBytes())));

        while(true && checkTicket==false){
            try {
                sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        // STEP 4
        String step4Data[] = messageTicket.split(SEPARATOR);
        tempArr = Base64.getDecoder().decode(step4Data[1].getBytes());
        tempArr = AesManager.decrypt(tempArr, Client.symmetricKey);
        String step4Block2 = new String(tempArr);
        String[] components = step4Block2.split(SEPARATOR);
        portUserToSend = Integer.valueOf(components[0]);
        Key serverPublicKey = RsaManager.getKeyFromFile(Client.SERVER_KEY_FILENAME, true);

        // Validate server signature of C2
        if(RsaManager.checkSignature(String.valueOf(nonceC2), components[1], serverPublicKey)){
            String ticketToDestinationUser = step4Data[2];

            Socket localClient = null;
            try {
                //connect with selected client
                localClient = new Socket("localhost", portUserToSend);

                //update comunication socket for this user
                for(int i=0; i<9 ; i++)
                {
                    if(availableUsers[i].getUser().equals(nameUserToSend)){
                        availableUsers[i].setClientChatSocket(localClient);
                        ReadListenerThread = new ClientManager(nameUserToSend,localClient);
                        ReadListenerThread.start();

                        String txt = "ticket" + SEPARATOR + ticketToDestinationUser + SEPARATOR + nameUserToSend ;


                        sendMessageToClient(nameUserToSend,txt);
                       /* byte[] data;
                        data = txt.getBytes();

                        try {
                            dataOutputStream = new DataOutputStream(availableUsers[i].getClientChatSocket().getOutputStream());
                            dataOutputStream.writeInt(data.length);
                            dataOutputStream.write(data);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }*/

                        break;
                    }
                }
            } catch (IOException e) {
                System.err.println("IOException:  " + e);
            }
        }
    }



    public static void printOnlineUsers(){
        System.out.println("-> Available Users <-");
        for(int i=0;i<9;i++) {
            if(availableUsers[i] != null)
                System.out.println(availableUsers[i].getUser() + ": " + availableUsers[i].getPort());
        }
    }

    public static void userAddRemove(String message){

        String[] user = message.split(Client.SPLIT_CHAR);
        int port = Integer.valueOf(user[1]);

        if(user[2].equals(0)){
            for(int i=0;i<9;i++) {
                if (availableUsers[i].getName().equals(user[0])) {
                    availableUsers[i] = null;
                    break;
                }
            }
        } else {
            for(int i=0;i<9;i++){
                if(availableUsers[i] == null){
                    availableUsers[i] = new User(user[0],Integer.valueOf(user[1]));
                    //System.out.println("Usuario agreado: " +  availableUsers[i].getUser() + " port: "+ availableUsers[i].getPort());
                    break;
                }
            }
        }
    }

    public static void sendMessageToClient(String username, String message){
        for (int i=0; i<9;i++)
        {
            if(availableUsers[i] != null) {
                if (availableUsers[i].getUser().equals(username)) {
                    try {
                        dataOutputStream = new DataOutputStream(availableUsers[i].getClientChatSocket().getOutputStream());
                        byte[] data;
                        data = message.getBytes();

                        dataOutputStream.writeInt(data.length);
                        dataOutputStream.write(data);

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }

    }
}
