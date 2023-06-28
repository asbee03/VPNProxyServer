import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class VPN {
    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        while (true) {
            Socket clientSocket = serverSocket.accept();
            Thread thread = new Thread(new ClientHandler(clientSocket));
            thread.start();
        }
    }
}

class ClientHandler implements Runnable {
    private Socket clientSocket;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            out.println("Welcome to the VPN!");


//still need to configure all the packages and uses for encryption

// The code starts by importing necessary classes, including `java.io.*`, `java.net.*`, `javax.crypto.*`, and `javax.crypto.spec.*`.
// The `VPN` class is defined, which contains methods for key generation, encryption, and decryption.
// The `setKey` method is used to generate a secret key based on the provided `myKey`. 
//It uses the SHA-1 algorithm to generate a hash of the key, truncates it to 16 bytes, 
//and creates a `SecretKeySpec` object for the AES (Advanced Encryption Standard) algorithm.
//The `encrypt` method takes a string `strToEncrypt` and a secret key `secret` as input and encrypts the string using AES encryption. 
//It uses ECB (Electronic Codebook) mode with PKCS5Padding for padding. The encrypted result is then Base64-encoded and returned as a string.
//The `decrypt` method takes a string `strToDecrypt` and a secret key `secret` as input and decrypts the string using AES decryption. 
//It performs the reverse operations of the encryption process, decoding the Base64 string and then decrypting it with AES. 
//The decrypted result is returned as a string.
//The `main` method serves as the entry point of the program. It creates a `ServerSocket` listening on port 12345.
//In an infinite loop, the code accepts incoming client connections using `serverSocket.accept()`. 
//When a client connects, a new `ClientHandler` thread is created to handle the client communication.
//The `ClientHandler` class is defined, which implements the `Runnable` interface for concurrent execution. 
//It takes the client socket as a constructor parameter.
//The `run` method is implemented in the `ClientHandler` class, which runs when the thread is started. 
//It reads from the client socket's input stream using a `BufferedReader`, and writes to the output stream using a `PrintWriter`.
//In this case, it sends the string "Welcome to the VPN!" to the client using `out.println()`.
