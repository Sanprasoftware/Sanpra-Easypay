// package hybrid;

// import java.io.FileInputStream;
// import java.io.FileNotFoundException;
// import java.io.IOException;
// import java.security.GeneralSecurityException;
// import java.security.InvalidKeyException;
// import java.security.Key;
// import java.security.KeyStore;
// import java.security.KeyStoreException;
// import java.security.NoSuchAlgorithmException;
// import java.security.UnrecoverableKeyException;
// import java.security.cert.CertificateException;
// import java.security.cert.CertificateFactory;
// import java.security.cert.X509Certificate;
// import java.util.Arrays;
// import java.util.Base64;
// import javax.crypto.BadPaddingException;
// import javax.crypto.Cipher;
// import javax.crypto.IllegalBlockSizeException;
// import javax.crypto.NoSuchPaddingException;
// import javax.crypto.spec.IvParameterSpec;
// import javax.crypto.spec.SecretKeySpec;

// public class Enc {
//     static final String SYMM_CIPHER = "AES/CBC/PKCS5PADDING";
//     static final String ASYMM_CIPHER = "RSA/ECB/PKCS1Padding";
//     static final String KEYSTORE_FILE = "server.p12";
//     static final String KEYSTORE_PWD = "123456789";
//     static final String KEYSTORE_ALIAS = "ICICI";
//     static final String PUBLIC_KEY = "server.crt";

//     public static void main(String[] args) throws Exception {
//         // Random Number
//         final String sessionKey = "qqqqwwww11112222";

//         // Payload
//         final String payload = "{"
//                 + "\"AGGRID\":\"BULK0079\","
//                 + "\"AGGRNAME\":\"BASTAR\","
//                 + "\"CORPID\":\"SESPRODUCT\","
//                 + "\"USERID\":\"HARUN\","
//                 + "\"URN\":\"SR263840153\","
//                 + "\"UNIQUEID\":\"hello123\""
//                 + "}";

//         // Random 16 bytes of IV
//         final String iv = "aaaabbbbccccdddd";

//         // Encrypt Payload Symmetrically
//         final String encryptedData = encryptSymm(sessionKey, iv, payload);

//         // Encrypt Session Key Asymmetrically
//         final String encryptedKey = encryptAsymm(Base64.getEncoder().encodeToString(sessionKey.getBytes()), PUBLIC_KEY);

//         // Create Final JSON Output
//         String finalJson = String.format("{\n" +
//                 "    \"requestId\": \"\",\n" +
//                 "    \"service\": \"LOP\",\n" +
//                 "    \"encryptedKey\": \"%s\",\n" +
//                 "    \"oaepHashingAlgorithm\": \"NONE\",\n" +
//                 "    \"iv\": \"%s\",\n" +
//                 "    \"encryptedData\": \"%s\",\n" +
//                 "    \"clientInfo\": \"\",\n" +
//                 "    \"optionalParam\": \"\"\n" +
//                 "}", encryptedKey, Base64.getEncoder().encodeToString(iv.getBytes()), encryptedData);

//         // Print Final JSON
//         System.out.println(finalJson);
//     }

//     public static String encryptSymm(String key, String initVector, String value) {
//         try {
//             IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
//             SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
//             Cipher cipher = Cipher.getInstance(SYMM_CIPHER);
//             cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
//             byte[] encrypted = cipher.doFinal(value.getBytes());
//             byte[] c = new byte[initVector.getBytes("UTF-8").length + encrypted.length];
//             System.arraycopy(initVector.getBytes("UTF-8"), 0, c, 0, initVector.getBytes("UTF-8").length);
//             System.arraycopy(encrypted, 0, c, initVector.getBytes("UTF-8").length, encrypted.length);
//             return Base64.getEncoder().encodeToString(c);
//         } catch (Exception ex) {
//             ex.printStackTrace();
//         }

//         return null;
//     }

//     public static String encryptAsymm(String b64Msg, String filePath)
//             throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException,
//             InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//         Cipher cipher = Cipher.getInstance(ASYMM_CIPHER);
//         Key key = loadPublicKeyFromFile(filePath);
//         byte[] msg = Base64.getDecoder().decode(b64Msg);
//         cipher.init(Cipher.ENCRYPT_MODE, key);
//         byte[] encryptedMsg = cipher.doFinal(msg);
//         return Base64.getEncoder().encodeToString(encryptedMsg);
//     }

//     private static Key loadPublicKeyFromFile(String publicKeyPath) throws CertificateException, FileNotFoundException {
//         Key key = null;
//         X509Certificate x509Certificate = createCert(publicKeyPath);
//         key = x509Certificate.getPublicKey();
//         return key;
//     }

//     private static X509Certificate createCert(String filePath) {
//         try {
//             CertificateFactory cf = CertificateFactory.getInstance("X509");
//             X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(filePath));
//             return cert;
//         } catch (Exception e) {
//             throw new RuntimeException(e);
//         }
//     }
// }


package hybrid;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Enc {
    static final String SYMM_CIPHER = "AES/CBC/PKCS5PADDING";
    static final String ASYMM_CIPHER = "RSA/ECB/PKCS1Padding";
    static final String PUBLIC_KEY = "server.crt";

    static final String API_URL = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/Create";
    static final String API_KEY = "SHUyF6MtXmvgtW1OnsWS6VWt1nAu4J2e"; // Replace with your API key

    public static void main(String[] args) throws Exception {
        // Random Session Key and IV
        final String sessionKey = "qqqqwwww11112222";
        final String iv = "aaaabbbbccccdddd";

        // Payload
        final String payload = "{"
                + "\"AGGRID\":\"BULK0079\","
                + "\"AGGRNAME\":\"BASTAR\","
                + "\"CORPID\":\"SESPRODUCT\","
                + "\"USERID\":\"HARUN\","
                + "\"URN\":\"SR263840153\","
                + "\"UNIQUEID\":\"hello123\""
                + "}";

        // Encrypt Payload
        String encryptedData = encryptSymmetric(sessionKey, iv, payload);
        String encryptedKey = encryptAsymmetric(Base64.getEncoder().encodeToString(sessionKey.getBytes()), PUBLIC_KEY);

        // Create Final JSON
        String finalJson = String.format("{\n" +
                "    \"requestId\": \"\",\n" +
                "    \"service\": \"LOP\",\n" +
                "    \"encryptedKey\": \"%s\",\n" +
                "    \"oaepHashingAlgorithm\": \"NONE\",\n" +
                "    \"iv\": \"%s\",\n" +
                "    \"encryptedData\": \"%s\",\n" +
                "    \"clientInfo\": \"\",\n" +
                "    \"optionalParam\": \"\"\n" +
                "}", encryptedKey, Base64.getEncoder().encodeToString(iv.getBytes()), encryptedData);
        System.out.println(finalJson);
        // Send API Request
        sendApiRequest(finalJson);
    }

    // Symmetric Encryption (AES)
    public static String encryptSymmetric(String key, String initVector, String value) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance(SYMM_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(value.getBytes());

        byte[] c = new byte[initVector.getBytes("UTF-8").length + encrypted.length];
        System.arraycopy(initVector.getBytes("UTF-8"), 0, c, 0, initVector.getBytes("UTF-8").length);
        System.arraycopy(encrypted, 0, c, initVector.getBytes("UTF-8").length, encrypted.length);

        return Base64.getEncoder().encodeToString(c);
    }

    // Asymmetric Encryption (RSA)
    public static String encryptAsymmetric(String b64Msg, String publicKeyPath) throws Exception {
        Cipher cipher = Cipher.getInstance(ASYMM_CIPHER);
        Key key = loadPublicKeyFromFile(publicKeyPath);
        byte[] msg = Base64.getDecoder().decode(b64Msg);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMsg = cipher.doFinal(msg);
        return Base64.getEncoder().encodeToString(encryptedMsg);
    }

    private static Key loadPublicKeyFromFile(String publicKeyPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(publicKeyPath));
        return cert.getPublicKey();
    }

    // API Request Method
    public static void sendApiRequest(String jsonPayload) {
        try {
            URL url = new URL(API_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("accept", "*/*");
            conn.setRequestProperty("APIKEY", API_KEY);
            conn.setDoOutput(true);

            // Send JSON Payload
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonPayload.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the Response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                System.out.println("Response: " + response.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
