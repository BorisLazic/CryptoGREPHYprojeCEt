package kripto;

import javafx.scene.control.Alert;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Encryption {

    public static BouncyCastleProvider cryptoProvider;

    static
    {
        Thread threadCryptoProvider = new Thread(() -> {
            cryptoProvider = new BouncyCastleProvider();
            Security.addProvider(cryptoProvider);
        });
        threadCryptoProvider.start();
    }

    static String getStringHashHexadecimal(String toBeHashed, String algorithm)
    {
        try {
            MessageDigest messageDigester = MessageDigest.getInstance(algorithm);
            messageDigester.update(toBeHashed.getBytes(StandardCharsets.UTF_8));
            byte[] digest = messageDigester.digest();
            return String.format("%x", new BigInteger(1, digest));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    static void codeEncryption(LoggedInUser sender, String recipient, String symmetricAlgorithm, String hashAlgorithm, File fileForEncryption)
    {
        if(!GUI.userIsRegistered(recipient))
            return;//ADD EXCEPTION TODO

        File destinationForEncryptedContent = new File(GUI.hashedUserList.getParent()
                + File.separatorChar + getStringHashHexadecimal(recipient, "SHA-256")
                + File.separatorChar + getStringHashHexadecimal(fileForEncryption.getName(),"SHA-256")+".txt");
        try(
                FileInputStream fileReader = new FileInputStream(fileForEncryption);
                PrintWriter encryptedFileWriter = new PrintWriter(destinationForEncryptedContent))
        {
            while (GUI.certificateAuthority == null)
                Thread.sleep(250);

            while (cryptoProvider == null)
                Thread.sleep(250);


            X509Certificate userCertificate = GUI.certificateAuthority.retrieveCertificate(recipient);
            userCertificate.checkValidity();

            byte[] fileContent = new byte[(int)fileForEncryption.length()];
            fileReader.read(fileContent);

            SecretKey sessionKey = symmetricKeyGenerator(symmetricAlgorithm);

            String encryptedHeader = encryptHeader(sender,symmetricAlgorithm,hashAlgorithm,sessionKey,userCertificate.getPublicKey());
            encryptedFileWriter.println(encryptedHeader);
            //encryptedFileWriter.println("*-*-*-*-*-*-Header_end*-*-*-*-*-*-");

            String symmetricEncryption = symmetricEncryption(fileContent,symmetricAlgorithm,sessionKey);
            encryptedFileWriter.println(symmetricEncryption);
            //encryptedFileWriter.println("*-*-*-*-*-*-Encrypted_file*-*-*-*-*-*-");

            String contentHash = getStringHashHexadecimal(encryptedHeader + symmetricEncryption, hashAlgorithm);
            encryptedFileWriter.println(contentHash);
            //encryptedFileWriter.println("*-*-*-*-*-*-Hash*-*-*-*-*-*-");

            String signedContentHash = digitalSigning(contentHash, readKey(sender.getUserName(),sender.getPassword()));
            encryptedFileWriter.println(signedContentHash);
            //encryptedFileWriter.println("*-*-*-*-*-*-Signed_hash*-*-*-*-*-*-");

            Alert boxAlert = new Alert(Alert.AlertType.INFORMATION, "File encrypted successfully");
            boxAlert.setTitle("Encryption");
            boxAlert.setHeaderText("File encrypted successfully");
            boxAlert.setResizable(false);
            boxAlert.setContentText("Press OK to continue crypting");
            boxAlert.showAndWait();

        }
        catch (IOException | CertificateExpiredException | CertificateNotYetValidException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static String encryptHeader(LoggedInUser sender, String encryptionAlgorithm, String hashAlgorithm, SecretKey sessionKey, PublicKey key)
    {
        try {
            String forEncryption = sender.getUserName() + "!!!" + encryptionAlgorithm+ "!!!" + hashAlgorithm + "!!!" + Base64.getEncoder().encodeToString(sessionKey.getEncoded());

            Cipher cipher = Cipher.getInstance("RSA", cryptoProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            return Base64.getEncoder().encodeToString(cipher.doFinal(forEncryption.getBytes(StandardCharsets.UTF_8)));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private static String digitalSigning(String hash, PrivateKey key)
    {
        try {
            Cipher cipher = Cipher.getInstance("RSA",cryptoProvider);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            return Base64.getEncoder().encodeToString(cipher.doFinal(hash.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String symmetricEncryption(byte[] forEncryption, String algorithm, SecretKey sessionKey)
    {
        try {

            Cipher cipher = Cipher.getInstance(algorithm.split("-")[0] + "/ECB/PKCS5Padding", cryptoProvider);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(forEncryption));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private static SecretKey symmetricKeyGenerator(String algorithm) throws Exception {
        try {
            KeyGenerator symmetricKeyGenerator = KeyGenerator.getInstance(algorithm.split("-")[0], cryptoProvider);

            switch (algorithm)
            {
                case "AES-192":
                    symmetricKeyGenerator.init(192);
                    break;
                case "AES-256":
                    symmetricKeyGenerator.init(256);
                    break;
                case "DESede":
                    symmetricKeyGenerator.init(168);
                    break;
                case "DES":
                    symmetricKeyGenerator.init(56);
                    break;
                default:
                    break;
            }

            return symmetricKeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        throw new Exception("Key not generated");
    }

    public static void codeDecryption(LoggedInUser loggedInUser, File forDecryption)
    {
        try(FileReader fr = new FileReader(forDecryption);
            BufferedReader bufferedReader = new BufferedReader(fr);
            PrintWriter printDecrypted = new PrintWriter(new FileWriter(new File(GUI.hashedUserList.getParent() +
                    File.separatorChar + getStringHashHexadecimal(loggedInUser.getUserName(),"SHA-256")+
                    File.separatorChar + "decrypted.txt")))) {

            while (GUI.certificateAuthority == null)
                Thread.sleep(250);
            while (cryptoProvider == null)
                Thread.sleep(250);

            PrivateKey userKey = readKey(loggedInUser.getUserName(),loggedInUser.getPassword());

            String headerEncrypted = bufferedReader.readLine();
            String[] decryptedHeaderParts = decryptHeader(headerEncrypted,userKey);

            String fileEncrypted = bufferedReader.readLine();
            String decryptedFile = symmetricDecrypt(fileEncrypted, decryptedHeaderParts[3],decryptedHeaderParts[1]);

            X509Certificate senderCertificate = GUI.certificateAuthority.retrieveCertificate(decryptedHeaderParts[0]);
            senderCertificate.checkValidity();

            String hashRead = bufferedReader.readLine();
            String hashCalculated = getStringHashHexadecimal(headerEncrypted + fileEncrypted, decryptedHeaderParts[2]);
            if(!hashCalculated.equals(hashRead)) {
                Alert boxAlert = new Alert(Alert.AlertType.ERROR, "Invalid Hash");
                boxAlert.setTitle("Decryption");
                boxAlert.setHeaderText("Calculated hash and read hash do not match.");
                boxAlert.setResizable(false);
                boxAlert.setContentText("Press OK to continue.");
                boxAlert.showAndWait();

            }

            if(!digitalVerification(hashRead,bufferedReader.readLine(),senderCertificate.getPublicKey())){
                Alert boxAlert = new Alert(Alert.AlertType.ERROR, "Invalid signature");
                boxAlert.setTitle("Decryption");
                boxAlert.setHeaderText("Signature invalid.");
                boxAlert.setResizable(false);
                boxAlert.setContentText("Press OK to continue.");
                boxAlert.showAndWait();
            }

            printDecrypted.println(decryptedFile);

        } catch (IOException | InterruptedException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String[] decryptHeader(String encryptedHeader, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

        Cipher cipher = Cipher.getInstance("RSA",cryptoProvider);
        cipher.init(Cipher.DECRYPT_MODE, key);
        String decryptedHeader = new String(cipher.doFinal(Base64.getDecoder().decode(encryptedHeader)),"UTF-8");
        return decryptedHeader.split("!!!");
    }

    private static String symmetricDecrypt(String encryptedContent, String symmetricKey, String encryptionAlgorithm)
    {
        try {
            String algorithmNoKeySize = encryptionAlgorithm.split("-")[0];
            Cipher cipher = Cipher.getInstance(algorithmNoKeySize + "/ECB/PKCS5Padding", cryptoProvider);

            byte[] sessionKeyBytes = Base64.getDecoder().decode(symmetricKey);
            SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, algorithmNoKeySize);

            cipher.init(Cipher.DECRYPT_MODE, sessionKey);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(encryptedContent));
            return new String(plainText, StandardCharsets.UTF_8);

        } catch (Exception ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private static boolean digitalVerification(String hash, String signedHash, PublicKey key)
    {
        try {
            Cipher cipher = Cipher.getInstance("RSA", cryptoProvider);
            cipher.init(Cipher.DECRYPT_MODE,key);
            byte[] array = cipher.doFinal(Base64.getDecoder().decode(signedHash));

            return hash.equals(new String(array, StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }



    public static void writeKey(String userName, String password, KeyPair keyPair) throws FileNotFoundException
    {
        File folder = new File(GUI.hashedUserList.getParent()+ File.separatorChar + getStringHashHexadecimal(userName,"SHA-256"));
        folder.mkdir();
        PrintWriter printKey = new PrintWriter(new File(folder.getPath() + File.separatorChar + "key.pem"));
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(printKey))
        {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC").build(password.toCharArray());
            JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(keyPair.getPrivate(), encryptor);
            pemWriter.writeObject(gen);
        } catch (IOException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static PrivateKey readKey(String userName, String password)
    {
        File folder = new File(GUI.hashedUserList.getParent() + File.separatorChar + getStringHashHexadecimal(userName,"SHA-256"));

        if(folder.exists())
        {
            try(PEMParser pemParser = new PEMParser(new FileReader(new File(folder.getAbsolutePath() + File.separatorChar + "key.pem"))))
            {
                Object wowObject = pemParser.readObject();
                PEMDecryptorProvider decryptionProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(cryptoProvider);
                KeyPair keyPair = null;
                if(wowObject instanceof PEMEncryptedKeyPair)
                    keyPair = keyConverter.getKeyPair(((PEMEncryptedKeyPair) wowObject).decryptKeyPair(decryptionProvider));

                return keyPair.getPrivate();

            } catch (FileNotFoundException ex) {
                Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
        return null;
    }
}