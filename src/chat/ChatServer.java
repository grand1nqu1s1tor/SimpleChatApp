package chat;

import encryption.Encryption;

import javax.swing.*;
import java.awt.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;


public class ChatServer extends JFrame implements Runnable {

    private static final String RSA = "RSA";
    private Key privateKey;
    private static final long serialVersionUID = 1L;
    private static int WIDTH = 400;
    private static int HEIGHT = 300;
    private int clientNum = 0;
    ArrayList<HandleClient> clients = new ArrayList<HandleClient>();
    private boolean disconnected = false;

    JTextArea textArea;
    JScrollPane scrollPane;
    ServerSocket serverSocket;

    public ChatServer() {

        super("Chat Server");

        try {
            privateKey = Encryption.readPrivateKey("keypairs/pkcs8_key");
            this.setSize(ChatServer.WIDTH, ChatServer.HEIGHT);
            this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            createMenu();

            textArea = new JTextArea(5, 10);
            textArea.setEditable(false);

            scrollPane = new JScrollPane(textArea);
            this.add(scrollPane, BorderLayout.CENTER);
            this.setVisible(true);


            Thread thread = new Thread(this);
            thread.start();
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("problem loading private key: " + e.getMessage());
            System.exit(1);
        }

    }

    private void createMenu() {
        JMenuBar menuBar = new JMenuBar();
        JMenu menu = new JMenu("File");
        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener((e) -> System.exit(0));
        menu.add(exitItem);
        menuBar.add(menu);
        this.setJMenuBar(menuBar);
    }


    public static void main(String[] args) {
        ChatServer chatServer = new ChatServer();
        chatServer.setVisible(true);
    }

    @Override
    public void run() {
        try {//create server socket
            serverSocket = new ServerSocket(9898);
            textArea.append("Chat Server started at socket 9898 on " + new Date());
            textArea.append("\nWaiting for connection from client\n");

            while (true) {
                Socket socket = serverSocket.accept();
                clientNum++;
                textArea.append("\nUser " + clientNum + " connect to server.\n");
                InetAddress inetAdd = socket.getInetAddress();
                textArea.append("\tUser's IP Address: " + inetAdd.getHostAddress() +
                        "\n\tUser's Host Name: " + inetAdd.getHostName());
                HandleClient clientThread = new HandleClient(clientNum, socket);
                clients.add(clientThread);
                clientThread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    public class HandleClient extends Thread {
        private Socket socket;
        private int clientNum;
        private DataInputStream inputFromClient;
        private DataOutputStream outputToClient;
        private Key aesKey;

        public HandleClient(int clientNum, Socket socket) {
            this.socket = socket;
            this.clientNum = clientNum;
        }

        @Override
        public void run() {
            try {
                inputFromClient = new DataInputStream(socket.getInputStream());
                outputToClient = new DataOutputStream(socket.getOutputStream());

                String msg = inputFromClient.readUTF();
                if ("HELLO".equals(msg)) {
                    outputToClient.writeUTF("CONNECTED");
                    int encryptedSeedLength = inputFromClient.readInt();
                    byte[] encryptedSeed = new byte[encryptedSeedLength];
                    inputFromClient.readFully(encryptedSeed, 0, encryptedSeedLength);
                    byte[] aesSeed = Encryption.pkDecrypt(privateKey, encryptedSeed);
                    System.out.println("Decrypted aesSeed from client " + Arrays.toString(aesSeed));

                    aesKey = Encryption.generateAESKey(aesSeed);
                    System.out.println("Generated key with bytes " + Arrays.toString(aesKey.getEncoded()));

                    while (!socket.isClosed()) {
                        int length = inputFromClient.readInt();
                        if (length > 0) {
                            byte[] message = new byte[length];
                            inputFromClient.readFully(message, 0, length);
                            String decryptedMessage = Encryption.decrypt(aesKey, new String(message)); // Decryption method might be different based on your Encryption class
                            System.out.println("Got message " + Base64.getEncoder().encodeToString(message));
                            System.out.println("Decrypted message to " + decryptedMessage);
                            broadcastMessage(decryptedMessage, this.clientNum);
                        }
                    }
                } else {
                    throw new IOException("Expected HELLO message, received something else");
                }
            } catch (IOException e) {
                System.err.println("Error handling client # " + clientNum + ": " + e.getMessage());
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Security Exception during handshake or message handling", e);
            } finally {
                try {
                    if (outputToClient != null) outputToClient.close();
                    if (inputFromClient != null) inputFromClient.close();
                    if (socket != null) socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                synchronized (clients) {
                    clients.remove(this);
                }
            }
        }


        private void broadcastMessage(String message, int senderClientNum) {
            synchronized (clients) {
                for (HandleClient client : clients) {
                    try {
                        if (client.clientNum != senderClientNum) {
                            String labeledMessage = "Client " + senderClientNum + ": " + message;
                            byte[] encryptedMessage = Encryption.encrypt(client.aesKey, labeledMessage).getBytes();
                            System.out.println("Encrypted message with bytes: " + Arrays.toString(encryptedMessage));
                            client.outputToClient.writeInt(encryptedMessage.length);
                            client.outputToClient.write(encryptedMessage);
                        }
                    } catch (IOException e) {
                        System.err.println("Error sending message to client #" + client.clientNum + ": " + e.getMessage());
                    } catch (GeneralSecurityException e) {
                        throw new RuntimeException("Encryption error: " + e.getMessage(), e);
                    }
                }
            }
        }


    }

}


