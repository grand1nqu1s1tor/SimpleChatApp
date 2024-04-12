package chat;

import encryption.Encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;


public class ChatClient extends JFrame implements Runnable, ActionListener {

    private static final String RSA = "RSA";
    private static final String SERVER_PUBLIC_KEY = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGk9wUQ4G9PChyL5SUkCyuHjTNOglEy5h4KEi0xpgjxi/UbIH27NXLXOr94JP1N5pa1BbaVSxlvpuCDF0jF9jlZw5IbBg1OW2R1zUACK+NrUIAYHWtagG7KB/YcyNXHOZ6Icv2lXXd7MbIao3ShrUVXo3u+5BJFCEibd8a/JD/KpAgMBAAE=";
    private PublicKey serverPublicKey;
    private Key communicationKey;

    private static final long serialVersionUID = 1L;
    private static int WIDTH = 400;
    private static int HEIGHT = 300;
    private boolean connectedServer = false;
    JTextArea chatArea;
    JTextField textField;
    JButton sendButton;
    JScrollPane scrollPane;
    JLabel connectionStatusLabel;
    Socket socket;
    DataInputStream inputFromServer;
    DataOutputStream outputToServer;
    private byte[] aesSeed;

    public ChatClient() {
        super("Chat Client");
        this.setSize(ChatClient.WIDTH, ChatClient.HEIGHT);
        createMenu();
        connectionStatusLabel = new JLabel("Not Connected to server");
        chatArea = new JTextArea(30, 30);
        chatArea.setText("Select Start Chat under the File menu to start chatting\n");
        chatArea.setForeground(Color.BLUE);
        chatArea.setEditable(false);
        scrollPane = new JScrollPane(chatArea);
        textField = new JTextField();
        textField.addActionListener(this);

        this.setLayout(new BorderLayout());
        this.add(connectionStatusLabel, BorderLayout.NORTH);
        this.add(scrollPane, BorderLayout.CENTER);
        this.add(textField, BorderLayout.SOUTH);
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setVisible(true);
        try {
            serverPublicKey = Encryption.readPublicKey(SERVER_PUBLIC_KEY);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("error getting server public key: " + e.getMessage());
        }

    }

    private void createMenu() {
        JMenuBar menuBar = new JMenuBar();
        JMenu menu = new JMenu("File");

        JMenuItem startChatItem = new JMenuItem("Start Chat");
        startChatItem.addActionListener(this);

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener(this);

        menu.add(startChatItem);
        menu.add(exitItem);

        menuBar.add(menu);
        this.setJMenuBar(menuBar);
    }

    public void run() {
    }

    public void actionPerformed(ActionEvent e) {

        if (e.getActionCommand().equals("Start Chat")) {
            if (connectedServer) {
                chatArea.append("You already to connect to the Server.\nYou can start chart in textfield.");
                return;
            }
            try {
                socket = new Socket("localhost", 9898);
                inputFromServer = new DataInputStream(socket.getInputStream());
                outputToServer = new DataOutputStream(socket.getOutputStream());
                connectionStatusLabel.setText("Connected");
                connectedServer = true;
                new Thread(new threadHandle()).start();
            } catch (IOException ex) {
                chatArea.append("Error Connecting to Server");
            }

        } else if (e.getSource() == textField && connectedServer) {
            try {
                String messageToSend = textField.getText();
                chatArea.append("You: " + messageToSend + "\n");
                textField.setText("");

                String encryptedMessage = Encryption.encrypt(communicationKey, messageToSend);
                byte[] message = encryptedMessage.getBytes();
                outputToServer.writeInt(message.length);
                outputToServer.write(message);
            } catch (IOException e1) {
                chatArea.append("Error sending message.\n");
            } catch (InvalidAlgorithmParameterException ex) {
                throw new RuntimeException(ex);
            } catch (NoSuchPaddingException ex) {
                throw new RuntimeException(ex);
            } catch (IllegalBlockSizeException ex) {
                throw new RuntimeException(ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException(ex);
            } catch (BadPaddingException ex) {
                throw new RuntimeException(ex);
            } catch (InvalidKeyException ex) {
                throw new RuntimeException(ex);
            }
        } else if (e.getActionCommand().equals("Exit")) {

            if (!connectedServer) {
                return;
            }
            try {
                outputToServer.writeUTF("sign out from chat");
                socket.close();
            } catch (IOException e1) {
                chatArea.append("Error closing connection\n");
            }
            System.exit(0);
        }
    }

    private class threadHandle extends Thread implements Runnable {
        public void run() {
            try {
                outputToServer.writeUTF("HELLO");
                String serverResponse = inputFromServer.readUTF();
                if ("CONNECTED".equals(serverResponse)) {
                    aesSeed = Encryption.generateSeed();
                    byte[] encryptedSeed = Encryption.pkEncrypt(serverPublicKey, aesSeed);
                    outputToServer.writeInt(encryptedSeed.length);
                    outputToServer.write(encryptedSeed);
                    communicationKey = Encryption.generateAESKey(aesSeed);
                    System.out.println("Generated key with bytes: " + Arrays.toString(communicationKey.getEncoded()));
                    SwingUtilities.invokeLater(() -> connectionStatusLabel.setText("Secure Connection Established"));
                    while (!socket.isClosed()) {
                        int length = inputFromServer.readInt();
                        if (length > 0) {
                            byte[] encryptedMessage = new byte[length];
                            inputFromServer.readFully(encryptedMessage, 0, length);
                            String decryptedMessage = Encryption.decrypt(communicationKey, new String(encryptedMessage, StandardCharsets.UTF_8));

                            String finalMessage = decryptedMessage + "\n";
                            SwingUtilities.invokeLater(() -> chatArea.append(finalMessage));
                        }
                    }
                } else {
                    chatArea.append("Failed to connect: " + serverResponse + "\n");
                }
            } catch (IOException | GeneralSecurityException e) {
                chatArea.append("Connection Lost or Error: " + e.getMessage() + "\n");
            } finally {
                try {
                    if (inputFromServer != null) inputFromServer.close();
                    if (outputToServer != null) outputToServer.close();
                    if (socket != null) socket.close();
                } catch (IOException ex) {
                }
                SwingUtilities.invokeLater(() -> connectionStatusLabel.setText("Disconnected"));
            }
        }

    }

    public static void main(String[] args) {
        ChatClient chatClient = new ChatClient();
        chatClient.setVisible(true);
    }
}
