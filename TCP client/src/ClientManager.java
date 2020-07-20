import java.io.DataInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;

public class ClientManager extends Thread implements Serializable {


    private String user;
    private Socket clientSocket = null;


    private DataInputStream receiveData = null;

    public ClientManager(String user, Socket clientSocket) {
        this.user = user;
        this.clientSocket = clientSocket;
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

    public void run() {
        int read;

        String result;
        byte[] complete;
        try {
            receiveData = new DataInputStream(getClientSocket().getInputStream());

            while (true) {
                String SEPARATOR = Client.SPLIT_CHAR;

                read = receiveData.readInt();
                //result = Client.receiveMessage(read);
                complete = new byte[read];
                receiveData.readFully(complete, 0, read);
                result = new String(complete);
                System.out.println("FROM CM: " + result);


                String[] data = result.split(SEPARATOR);
                switch (data[0]) {
                    case "step2":
                        System.out.println("FROM CM: " + "MUAJAJAJJAJAJAJAJAJJAJAJ");

                        break;
                    default:
                        break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
