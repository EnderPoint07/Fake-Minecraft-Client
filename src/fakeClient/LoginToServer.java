package fakeClient;

import fakeClient.lib.AccountAPI.*;
//import fakeClient.lib.jzlib.*;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.*;

public class LoginToServer {
    
    static DataOutputStream output = null;
    static DataInputStream input = null;
    static CipherInputStream cipherInput = null;
    static CipherOutputStream cipherOutput = null;
    static InflaterInputStream decomprInput = null;
    static DeflaterOutputStream comprOutput = null;

    public static void main(String [] args) throws Exception {

        String address = "127.0.0.1";
        String username = "EnderPoint_07";
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
        byte [] loginMessage = createLoginStartMessage(username);
        // C->S : Login Start
        writeVarInt(output, loginMessage.length);
        output.write(loginMessage);
        System.out.println("Done!");

        System.out.println("Reading Encryption Request...");
        // S->C : Encryption Request
        readVarInt(input); // Packet size
        int packetId = readVarInt(input); // Packet id

        if (packetId != 0x01) { // we want encryption request
            System.out.println("Packet id was: " + packetId);
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

        System.out.println("Creating account");

        MicrosoftAccount Account = new MicrosoftAccount();

        System.out.println("Creating Shared Secret...");
        // Generate the shared secret
        Key secret = getSecureRandomKey("AES", 128);

        System.out.println("Generating the shah1_hash...");
        String sha1Hash = generateHash(serverId.getBytes(StandardCharsets.UTF_8), secret.getEncoded(), publicKeyBytes, "SHA1");
        System.out.println("shah1Hash: "+sha1Hash);

        String payload = "{" +
                            "\"accessToken\": \"%TOKEN%\"," +
                            "\"selectedProfile\": \"%UUID%\"," +
                            "\"serverId\": \"%HASH%\"" +
                         "}";

        System.out.println("UUID: "+ Account.getUuid().toString());

        String response = Utils.sendAndRecieveJson(
                "https://sessionserver.mojang.com/session/minecraft/join",
                payload.replace("%TOKEN%", Account.getAccessToken()).replace("%HASH%", sha1Hash).replace("%UUID%",
                        Account.getUuid().toString()),
                true
        );

        System.out.println("response: " + response);

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

        System.out.println("Enabling Encryption on both sides");

        // Enable Encryption/Decryption of packets
        setUpCipherStreams(secret.getEncoded());

        // S -> C Set compression packet
        int compressionPacketSize = readVarInt(cipherInput);
        int compressionPacketId = readVarInt(cipherInput);

        int Threshold = 0;
        if (compressionPacketId == 0x03) {
            Threshold = readVarInt(cipherInput);
            System.out.println("Compression Threshold: " + Threshold);
        }else {
            System.out.println("No compression");
        }

        // Set up compression/decompression
        System.out.println("Setting up compression/decompression...");
        setUpCompressionStreams();

        // S->C Login Success
        int loginPacketLength = readVarInt(cipherInput); // Length of Data Length + compressed length of (Packet ID + Data)
        int loginPacketDataLength = readVarInt(cipherInput); // Length of uncompressed (Packet ID + Data) or 0

        System.out.println("loginPacketLength: " + loginPacketLength);
        System.out.println("loginPacketDataLength: " + loginPacketDataLength);

        int loginPacketId = readVarInt(cipherInput);

        System.out.println("loginPacketId: " + loginPacketId);



        if(loginPacketId != 0x02) { // We want login success
            System.out.println("Bad packet id: " + loginPacketId);

            if(loginPacketId == 0x00) { // If it's a disconnect packet
                disconnected(cipherInput);
            }
            return;
        }

        byte[] LUuidBytes = cipherInput.readNBytes(16);

        ByteBuffer byteBuffer = ByteBuffer.wrap(LUuidBytes);
        long high = byteBuffer.getLong();
        long low = byteBuffer.getLong();
        UUID LUuid = new UUID(high, low);
        System.out.println("LUuid: " + LUuid);

        String LUsername = new String(cipherInput.readNBytes(16), StandardCharsets.UTF_8);
        System.out.println("LUsername: " + LUsername);

//        int aarLen = readVarInt(cipherInput);
//        System.out.println("Number of indexes: " + aarLen);

        String Name = new String(cipherInput.readNBytes(32767), StandardCharsets.ISO_8859_1);
        System.out.println("Name: " + Name);

        System.out.println("Done");
    }

    static void setUpCompressionStreams() {
        comprOutput = new DeflaterOutputStream(cipherOutput);
        decomprInput = new InflaterInputStream(cipherInput);
    }

    private static String generateHash(byte[] serverIdBytes, byte[] secretBytes, byte[] publicKeyBytes,
                                       String ALGORITHM) throws Exception {

        MessageDigest digest = MessageDigest.getInstance(ALGORITHM);

        digest.update(serverIdBytes);
        digest.update(secretBytes);
        digest.update(publicKeyBytes);

        return new BigInteger(digest.digest()).toString(16);
    }

    public static void disconnected(DataInputStream input) throws IOException {
        int disconnectReasonLen = readVarInt(input); // disconnect reason length
        byte[] disconnectReasonBytes = new byte[disconnectReasonLen]; // disconnect reason bytes
        input.readFully(disconnectReasonBytes);
        String disconnectReason = new String(disconnectReasonBytes);

        throw new IOException("Disconnect reason: " + disconnectReason);
    }

    public static void disconnected(CipherInputStream input) throws IOException {
        int disconnectReasonLen = readVarInt(input); // disconnect reason length
        byte[] disconnectReasonBytes = new byte[disconnectReasonLen]; // disconnect reason bytes

        input.read(disconnectReasonBytes);

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
    public static byte [] createLoginStartMessage(String username) throws IOException {
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

    public static void setUpCipherStreams(byte[] secretKey) throws Exception {

        // Make the IV
        IvParameterSpec iv = new IvParameterSpec(secretKey);

        // Set up the cipher input/decrypt stream
        SecretKey Skey = new SecretKeySpec(secretKey, "AES"); // Make the secret key


        Cipher decryptCipher = Cipher.getInstance("AES/CFB8/NoPadding"); // Make the cipher
        decryptCipher.init(Cipher.DECRYPT_MODE, Skey, iv); // set to decrypt mode

        // Set up the cipher output/encrypt stream
        Cipher encryptCipher = Cipher.getInstance("AES/CFB8/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, Skey, iv);


        cipherInput = new CipherInputStream(input, decryptCipher); // Set the CipherInputStream to decrypt the in stream
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
    public static int readVarInt(InflaterInputStream input) throws IOException {
        int i = 0;
        int j = 0;
        while (true) {
            int k = input.read();

            i |= (k & 0x7F) << j++ * 7;
            if (j > 5) throw new RuntimeException("VarInt too big");
            if ((k & 0x80) != 128) break;
        }
        return i;
    }


}
