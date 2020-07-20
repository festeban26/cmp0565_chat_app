package com.company;

import java.io.PrintStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class Main {

    private static String HASHING_ALGORITHM= "SHA-256";
    private static Charset CHARSET = StandardCharsets.UTF_8;

        private static ServerSocket serverSocket = null;
        private static Socket clientSocket = null;
        // Available connections for server
        private static final int listenToPort = 2222;
        private static final int maxClientsCount = 10;
        private static final ClientThread[] threads = new ClientThread[maxClientsCount];

    public static void main(String args[]) {

        // SERVER START listening for new clients
        try {
            serverSocket = new ServerSocket(listenToPort);
        } catch (IOException e) {
            System.out.println(e);
        }

        System.out.println("SERVER STARTED\n IP: " + serverSocket.getLocalSocketAddress()+ " PORT: "+ serverSocket.getLocalPort() );

        //Create a client socket for each connection and pass it to a new client thread.
        while (true) {
            try {
                clientSocket = serverSocket.accept();
                System.out.println("incoming connection ip " + clientSocket.getInetAddress() + " port " + clientSocket.getPort());

                int i;
                for (i = 0; i < maxClientsCount; i++) {
                    if (threads[i] == null) {
                        (threads[i] = new ClientThread(clientSocket, threads, Main.HASHING_ALGORITHM, Main.CHARSET)).start();

                        break;
                    }
                }

                if (i == maxClientsCount) {
                    PrintStream os = new PrintStream(clientSocket.getOutputStream());
                    os.println("Server too busy. Try later.");
                    os.close();
                    clientSocket.close();
                }
            } catch (IOException e) {
                System.out.println(e);
            }
        }
    }
}

