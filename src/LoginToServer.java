import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class LoginToServer {

    static DataOutputStream output = null;
    static DataInputStream input = null;
    static CipherInputStream cipherInput = null;
    static CipherOutputStream cipherOutput = null;

    public static void main(String [] args) throws Exception {

        String address = "127.0.0.1";
        String username = "EnderPoint_07";
        String UUID = "1f81ba9c55674a32bb38cdd3be13ba97";
        int port = 25565;

        InetSocketAddress host = new InetSocketAddress(address, port);
        Socket socket = new Socket();
        System.out.println("Connecting...");
        socket.connect(host, 3000);
        System.out.println("Done!");
        System.out.println("Making streams...");
        output = new DataOutputStream(socket.getOutputStream());
        input = new DataInputStream(socket.getInputStream());
        System.out.println("Done!");

        System.out.println("Attempting handshake... "+host.getAddress().toString());
        byte [] handshakeMessage = createHandshakeMessage(address, port);
        // C->S : Handshake State= 2
        // send packet length and packet
        writeVarInt(output, handshakeMessage.length);
        output.write(handshakeMessage);

        System.out.println("Attempting Login..."+ username);
        byte [] loginMessage = createLoginStartMessage(username, UUID);
        // C->S : Login Start
        writeVarInt(output, loginMessage.length);
        output.write(loginMessage);
        System.out.println("Done!");

        System.out.println("Reading Encryption Request...");
        // S->C : Encryption Request
        readVarInt(input); // Packet size
        int packetId = readVarInt(input); // Packet id

        if (packetId != 0x01) { // we want encryption request
            disconnected(input);
        }

        // Read the server id (Empty)
        int length = readVarInt(input); // length of the string
        byte[] serverIdBytes = new byte[length]; // make byte array of the length of string
        input.readFully(serverIdBytes); // read the server id from the packet and put it into the byte array
        String serverId = Base64.getEncoder().encodeToString(serverIdBytes); // make it into string

        // Read the public key
        int publicKeyLen = readVarInt(input);
        byte[] publicKeyBytes = new byte[publicKeyLen];
        input.readFully(publicKeyBytes);
        String publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);

        // Read the verifyToken
        int verifyTokenLen = readVarInt(input);
        byte[] verifyTokenBytes = new byte[verifyTokenLen];
        input.readFully(verifyTokenBytes);
        String verifyToken = Base64.getEncoder().encodeToString(verifyTokenBytes);

        System.out.println("Server Id: "+serverId);
        System.out.println("Public Key: \n"+publicKey);
        System.out.println("Verify Token: "+verifyToken);

        System.out.println("Done!");

        System.out.println("Creating Shared Secret...");
        // Generate the shared secret
        final String CIPHER = "AES";
        Key secret = getSecureRandomKey(CIPHER, 128);

        System.out.println("Encrypting the shared secret...");

        // Encrypt the secret and secretLength with server's public key
        byte[] encryptedSecret = encrypt(publicKeyBytes, secret.getEncoded(), "RSA");

        System.out.println("Done!");

        System.out.println("Encrypting the Verify Token...");
        // Encrypt the VerifyToken with server's public key
        byte[] encryptedVerifyToken = encrypt(publicKeyBytes, verifyTokenBytes, "RSA");

        System.out.println("Done!");

        System.out.println("Proceeding with Encryption Response...");
        byte[] encryptionResponse = encryptionResponse(encryptedSecret.length, encryptedSecret,
                encryptedVerifyToken.length, encryptedVerifyToken);
        // C->S Encryption Response
        writeVarInt(output, encryptionResponse.length);
        output.write(encryptionResponse);


        System.out.println("Response length: " + encryptionResponse.length + " Response: " + Arrays.toString(encryptionResponse));
        System.out.println("Done!");

        // Enable Encryption/Decryption of packets
        setUpCipherStreams(publicKeyBytes, secret.getEncoded());

        // S->C Login Success
        int loginPacketSize = readVarInt(cipherInput); // packet size
        int loginPacketId = readVarInt(cipherInput); // packet id

        if(loginPacketId != 0x02) { // We want login success
            System.out.println("Bad packet id: " + loginPacketId);

            if(loginPacketId == 0x00) { // If it's a disconnect packet
                disconnected(input);
            }
        }

        System.out.println("Done");
    }

    public static void disconnected(DataInputStream input) throws IOException {
        int disconnectReasonLen = readVarInt(input); // disconnect reason length
        byte[] disconnectReasonBytes = new byte[disconnectReasonLen]; // disconnect reason bytes
        input.readFully(disconnectReasonBytes);
        String disconnectReason = new String(disconnectReasonBytes);

        throw new IOException("Disconnect reason: " + disconnectReason);
    }

    public static byte [] createHandshakeMessage(String host, int port) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        DataOutputStream handshake = new DataOutputStream(buffer);
        handshake.writeByte(0x00); //packet id for handshake
        writeVarInt(handshake, 759); //protocol version
        writeString(handshake, host, StandardCharsets.UTF_8);
        handshake.writeShort(port); //port
        writeVarInt(handshake, 2); //state (2 for login)

        return buffer.toByteArray();
    }
    public static byte [] createLoginStartMessage(String username, String UUID) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        DataOutputStream login = new DataOutputStream(buffer);
        login.writeByte(0x00); //packet id for login
        writeString(login, username, StandardCharsets.UTF_8);
        login.writeBoolean(false); //do not send sig stuff
        //login.writeBoolean(true); // send UUID
        //writeString(login, UUID, StandardCharsets.UTF_8);

        return buffer.toByteArray();
    }
    public static byte [] encryptionResponse(int secretLen, byte[] secret, int tokenLen, byte[] token) throws IOException {
        ByteArrayOutputStream buffers = new ByteArrayOutputStream();

        DataOutputStream response = new DataOutputStream(buffers);

        System.out.println(secretLen + " " + tokenLen);
        System.out.println("Secret: " + Arrays.toString(secret));
        System.out.println("Token: " + Arrays.toString(token));


        response.writeByte(0x01); //packet id for Encryption Response

        writeVarInt(response, secretLen); //secret length
        for (byte b : secret){ // send secret
            response.writeByte(b);
        }

        response.writeBoolean(true); // we have the verifyToken
        writeVarInt(response, tokenLen); // send the length of token
        for (byte b : token){ // send the token
            response.writeByte(b);
        }

        return buffers.toByteArray();
    }

    private static Key getSecureRandomKey(String cipher, int KeySize) {
        byte[] secureRandomKeyBytes = new byte[KeySize/8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secureRandomKeyBytes);

        return new SecretKeySpec(secureRandomKeyBytes, cipher);
    }

    public static byte[] encrypt(byte[] publicKey, byte[] data, String ALGORITHM) throws Exception {
        PublicKey key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data);

        return encryptedBytes;
    }

    public static void setUpCipherStreams(byte[] publicKey, byte[] secretKey) throws Exception {

        // Make the IV
        IvParameterSpec iv = new IvParameterSpec(secretKey);
        // Set up the cipher input/decrypt stream
        SecretKey Skey = new SecretKeySpec(secretKey, "AES"); // Make the secret key
        Cipher decryptCipher = Cipher.getInstance("AES/CFB/NoPadding"); // Make the cipher
        decryptCipher.init(Cipher.DECRYPT_MODE, Skey, iv); // set to decrypt mode

        cipherInput = new CipherInputStream(input, decryptCipher); // Set the CipherInputStream to decrypt the in stream

        // Set up the cipher output/encrypt stream
        PublicKey Pkey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, Pkey);

        cipherOutput = new CipherOutputStream(output, encryptCipher);
    }

    public static void writeString(DataOutputStream out, String string, Charset charset) throws IOException {
        byte [] bytes = string.getBytes(charset);
        writeVarInt(out, bytes.length);
        out.write(bytes);
    }

    public static void writeVarInt(DataOutputStream out, int paramInt) throws IOException {
        while (true) {
            if ((paramInt & 0xFFFFFF80) == 0) {
                out.writeByte(paramInt);
                return;
            }

            out.writeByte(paramInt & 0x7F | 0x80);
            paramInt >>>= 7;
        }
    }

    public static int readVarInt(DataInputStream in) throws IOException {
        int i = 0;
        int j = 0;
        while (true) {
            int k = in.readByte();
            i |= (k & 0x7F) << j++ * 7;
            if (j > 5) throw new RuntimeException("VarInt too big");
            if ((k & 0x80) != 128) break;
        }
        return i;
    }

    public static int readVarInt(CipherInputStream cipher) throws IOException {
        int i = 0;
        int j = 0;
        while (true) {
            int k = cipher.read();

            i |= (k & 0x7F) << j++ * 7;
            if (j > 5) throw new RuntimeException("VarInt too big");
            if ((k & 0x80) != 128) break;
        }
        return i;
    }

}