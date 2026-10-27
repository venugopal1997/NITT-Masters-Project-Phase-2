package sample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECC {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\file400M.zip"));

        Long start, end;
        start = System.currentTimeMillis();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        Cipher cipher_e = Cipher.getInstance("ECIESwithAES-CBC", "BC");
        byte[] nonce_e = new byte[16];
        new SecureRandom().nextBytes(nonce_e);
        IESParameterSpec iesSpec_e = new IESParameterSpec(null, null, 256, 256, nonce_e);
        cipher_e.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), iesSpec_e);
        byte[] encryptedBytes = cipher_e.doFinal(originalBytes);

        Cipher cipher_d = Cipher.getInstance("ECIESwithAES-CBC", "BC");
        byte[] nonce_d = new byte[16];
        new SecureRandom().nextBytes(nonce_d);
        IESParameterSpec iesSpec_d = new IESParameterSpec(null, null, 256, 256, nonce_e);
        cipher_d.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), iesSpec_d);
        byte[] decryptedBytes = cipher_d.doFinal(encryptedBytes);

        System.out.println("Original == Decrypted ? => " + Arrays.equals(originalBytes, decryptedBytes));

        end = System.currentTimeMillis();
        System.out.println("Time taken for Signature Validation: " + ((end - start) / 1000.0) + " seconds");
    }
}
