import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

public class User extends Thread implements Serializable{


    private String user;
    private int port;
    private boolean ticket = false;

    private static ServerSocket clientListener = null;
    private Socket clientSocket = null;

    private DataInputStream receiveData = null;
    private DataOutputStream sendData = null;

    private Socket clientChatSocket = null;


    public ClientManager ReadListenerThread;


    public Socket getClientChatSocket() {
        return clientChatSocket;
    }

    public void setClientChatSocket(Socket clientChatSocket) {
        this.clientChatSocket = clientChatSocket;
    }

    public User(String user, int port){
        this.user = user;
        this.port = port;
    }

    public Socket getClientSocket() {
        return clientSocket;
    }

    public void setClientSocket(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isTicket() {
        return ticket;
    }

    public void setTicket(boolean ticket) {
        this.ticket = ticket;
    }

    public void run() {
        try {
            clientListener = new ServerSocket(port);
        } catch (IOException e) {
            System.out.println(e);
        }
        int read;
        String incomingMessage;
        String[] userConnection;
        byte[] complete;

        String SEPARATOR = Client.SPLIT_CHAR;

        while (true) {
            try{
                clientSocket = clientListener.accept();
                receiveData = new DataInputStream(clientSocket.getInputStream());
                sendData = new DataOutputStream(clientSocket.getOutputStream());
                PublicKey friendRsaPublicKey = null;
                PublicKey friendDhPublicKey = null;

                //incomingMessage= Client.receiveMessage(read);

                read = receiveData.readInt();
                //incomingMessage= Client.receiveMessage(read);
                complete = new byte[read];
                receiveData.readFully(complete, 0, read);
                incomingMessage = new String(complete);

                String[] data = incomingMessage.split(SEPARATOR);
                switch (data[0]) {
                    case "ticket":
                        SecretKey symmetricKey = Client.symmetricKey;
                        byte[] tempArr;
                        StringBuilder sb = new StringBuilder();
                        tempArr = Base64.getDecoder().decode(data[1]);
                        tempArr = AesManager.decrypt(tempArr, symmetricKey);
                        String step1Block2 = new String(tempArr);

                        String[] components_step1Block2 =  step1Block2.split(SEPARATOR);
                        String friendUsername = components_step1Block2[0];
                        friendRsaPublicKey = RsaManager.getDecodedPublicKey(components_step1Block2[1].getBytes());
                        tempArr = Base64.getDecoder().decode(components_step1Block2[2].getBytes());
                        friendDhPublicKey = DhManager.getDecodedPublicKey(tempArr);

                        // STEP 2
                        //  creates his own DH key pair from Alice public key associated params (g, p)
                        KeyPair keyPair = DhManager.getAKeyPairFromAssociatedDhParametersOfPublicKey(friendDhPublicKey);
                        // Bob initialize his DH Key Agreements
                        KeyAgreement keyAgreement = DhManager.getKeyAgreement(keyPair.getPrivate());

                        // Bob send his public key to Alice
                        byte[] myEncodedPublicKey = DhManager.getEncodedPublicKey(keyPair.getPublic());
                        String myEncodedPublicKey_asString =
                                new String(Base64.getEncoder().encode(myEncodedPublicKey));

                        sb = new StringBuilder();
                        sb.append("step2").append(SEPARATOR).append(myEncodedPublicKey_asString);
                        String temp = String.valueOf(sb);
                        byte[] message = temp.getBytes();
                        sendData.writeInt(message.length);
                        sendData.write(message);

                        break;
                    case "step2":
                        System.out.println("Esteban Flores");
                        break;
                    default:
                        break;
                }

                for (int i=0;i<9;i++){
                    if(Client.availableUsers[i] != null ){
                        if (Client.availableUsers[i].getUser().equals(String.valueOf(data[2]))){
                            Client.availableUsers[i].setClientChatSocket(clientSocket);
                            break;
                        }
                    }
                }
                ReadListenerThread = new ClientManager(String.valueOf(data[0]),clientSocket);
                ReadListenerThread.start();


            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void sendMessage(String data){

        byte[] message;
        message = data.getBytes();
        try {
            sendData.writeInt(message.length);
            sendData.write(message);
        } catch (IOException e) { e.printStackTrace(); }
    }
}
