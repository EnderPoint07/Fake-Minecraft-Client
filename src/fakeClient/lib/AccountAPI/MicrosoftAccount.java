//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package fakeClient.lib.AccountAPI;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import fakeClient.lib.AccountAPI.Utils;

/**
 * This is an Implementation of the Microsoft Minecraft Account
 * @author Pancake
 *
 * Modified by EnderPoint
 * @author EnderPoint
 */
public final class MicrosoftAccount {

    /** Cached Access Token for Microsoft Account */
    private final String refreshToken;

    private final String accessToken;
    private final String username;
    private final UUID uuid;
    private final boolean ownsMinecraft;

    /**
     * Create a Microsoft Account via Web View.
     * @throws Exception Throws an Exception when the Microsoft Servers do
     */
    public MicrosoftAccount() throws Exception {
        /* Obtain Auth Code from Login Process */

        // https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id=f825dd16-a6d5-44f8-ab1c-836af116bfa3&response_type=code&redirect_uri=http://localhost:28562&response_mode=query&scope=XboxLive.signin&prompt=select_account
        Utils.openBrowser("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" +
                "client_id=f825dd16-a6d5-44f8-ab1c-836af116bfa3" +
                "&response_type=code" +
                "&redirect_uri=http://localhost:28562" +
                "&response_mode=query" +
                "&scope=XboxLive.signin" +
                "&prompt=select_account");

        final ServerSocket socket = new ServerSocket(28562); // Note: The Redirect address is localhost, so we setup a small http server
        final Socket s = socket.accept();
        final BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
        final String authCode = in.readLine().substring(11).split(" ")[0];

        System.out.println("authCode: " + authCode);

        String output = "HTTP/1.0 200 OK\r\n" +
                "Server: AccountAPI Fake-Server/1.0\r\n" +
                "Content-type: text/html\r\n" +
                "\r\n";
        s.getOutputStream().write(output.getBytes(StandardCharsets.UTF_8));
        s.getOutputStream().flush();

        /* Connect to Xbox live servers to obtain XSTS */
        String localToken = null;
        String localRefreshToken = null;
        try {
            final String accessTokenResponse = Utils.acquireAccessToken(authCode);
            System.out.println("accessTokenResponse: " + accessTokenResponse);

            localToken = login(accessTokenResponse.split("access_token\"")[1].split("\"")[1]);
            System.out.println("minecraftAccessToken: " + localToken);

            localRefreshToken = accessTokenResponse.split("refresh_token\"")[1].split("\"")[1];
            System.out.println("localRefreshToken: " + localRefreshToken);

            s.getOutputStream().write("Login finished, you can close this page now! :)\r\n".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            s.getOutputStream().write("Something went wrong!\r\n".getBytes(StandardCharsets.UTF_8));
            e.printStackTrace();
        }
        accessToken = localToken;
        refreshToken = localRefreshToken;
        s.getOutputStream().flush();
        s.close();
        socket.close();

        /* Checking Game Ownership */
        final String ownershipJson = Utils.sendAndRecieveJson("https://api.minecraftservices.com/entitlements/mcstore", null, false, "Authorization", "Bearer " + accessToken);
        ownsMinecraft = !ownershipJson.replaceAll(" ", "").contains("[]");
        if (!ownsMinecraft) {
            uuid = null;
            username = null;
            System.out.println("Imagine not owning Minecraft");
            return;
        }

        /* Checking the Profile */
        final String profileJson = Utils.sendAndRecieveJson("https://api.minecraftservices.com/minecraft/profile", null, false, "Authorization", "Bearer " + accessToken);
        uuid = UUID.fromString(profileJson.split("id\"")[1].split("\"")[1].replaceFirst("(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)", "$1-$2-$3-$4-$5"));
        username = profileJson.split("name\"")[1].split("\"")[1];
    }

    /**
     * Refresh an existing Account Token and create accounts from that.
     * Does not require a Web View
     * @param Account Token from older Log-in
     */
    public MicrosoftAccount(final String refreshToken) throws Exception {
        this.refreshToken = Utils.refreshAccessToken(refreshToken);
        this.accessToken = login(this.refreshToken);

        /* Checking Game Ownership */
        final String ownershipJson = Utils.sendAndRecieveJson(
                "https://api.minecraftservices.com/entitlements/mcstore",
                null,
                false,
                "Authorization", "Bearer " + accessToken
        );
        ownsMinecraft = !ownershipJson.replaceAll(" ", "").contains("[]");
        if (!ownsMinecraft) {
            uuid = null;
            username = null;
            return;
        }

        /* Checking the Profile */
        final String profileJson = Utils.sendAndRecieveJson("https://api.minecraftservices.com/minecraft/profile", null, false, "Authorization", "Bearer " + accessToken);
        uuid = UUID.fromString(profileJson.split("id\"")[1].split("\"")[1].replaceFirst("(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)", "$1-$2-$3-$4-$5"));
        username = profileJson.split("name\"")[1].split("\"")[1];
    }

    /**
     * Obtain Access Token, used from Constructors only
     * @return Access Token of Minecraft Account
     */
    private final String login(final String localAccountToken) throws IOException {
        final String xblToken = Utils.getXBLToken(localAccountToken);
        System.out.println("xblToken: " + xblToken);

        final String xstsTokenJson = Utils.getXSTSToken(xblToken);
        System.out.println("xstsTokenJson: " + xstsTokenJson);

        // Parse 2 instead of 1 variable from JSON
        final String xstsToken = xstsTokenJson.split("Token\"")[1].split("\"")[1];
        System.out.println("xstsToken: " + xstsToken);

        final String uhs = xstsTokenJson.split("uhs\"")[1].split("\"")[1];
        System.out.println("uhs: " + uhs);

        final String accessToken =  Utils.getAccessToken(xstsToken, uhs);

        return accessToken;
    }

    /**
     * Private Constructor used for Cloning
     */
    MicrosoftAccount(final String accessToken, final String username, final UUID uuid, final boolean ownsMinecraft, final String account) {
        this.accessToken = accessToken;
        this.username = username;
        this.uuid = uuid;
        this.ownsMinecraft = ownsMinecraft;
        this.refreshToken = account;
        System.out.println(account);
    }

    /* Getters */

    public final String getAccessToken() {
        return accessToken;
    }

    public final String getUsername() {
        return username;
    }

    public final UUID getUuid() {
        return uuid;
    }

    public final boolean ownsMinecraft() {
        return ownsMinecraft;
    }

    public final String getAccountToken() {
        return refreshToken;
    }


    /* General Java Stuff */

    /**
     * Clones a Minecraft Account without Connecting to a Server again
     */
    @Override
    protected Object clone() throws CloneNotSupportedException {
        return new MicrosoftAccount(accessToken, username, uuid, ownsMinecraft, refreshToken);
    }

    /**
     * Create a Hash of the Player UUID
     */
    @Override
    public int hashCode() {
        return uuid.hashCode();
    }

    /**
     * Check whether two Accounts are equal
     */
    @Override
    public boolean equals(Object o) {
        return o.hashCode() == hashCode();
    }

    /**
     * To String support because why not
     */
    @Override
    public String toString() {
        return uuid.toString();
    }

}
