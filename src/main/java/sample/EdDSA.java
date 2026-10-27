package sample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

public class EdDSA {

    public static byte[] GenerateSignature(byte[] originalBytes, KeyPair keys) throws SignatureException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaSign = Signature.getInstance("Ed25519", "BC");
        ecdsaSign.initSign(keys.getPrivate());
        ecdsaSign.update(originalBytes);
        byte[] signature = ecdsaSign.sign();
        return signature;
    }

    public static boolean ValidateSignature(byte[] originalBytes, KeyPair pair, byte[] signature) throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaVerify = Signature.getInstance("Ed25519", "BC");
        ecdsaVerify.initVerify(pair.getPublic());
        ecdsaVerify.update(originalBytes);
        return ecdsaVerify.verify(signature);
    }

    public static KeyPair GenerateKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519", "BC");
        return g.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Long start, end;
        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\file800.zip"));

        System.out.println("Key Generation started: ");
        start = System.currentTimeMillis();
        KeyPair keys = GenerateKeys();
//		System.out.println(keys.getPublic().toString());
//		System.out.println(keys.getPrivate().toString());
        System.out.println("Key Generation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Time taken for Key Generation: " + ((end - start) / 1000.0) + " seconds");

        System.out.println("Signature Generation started: ");
        start = System.currentTimeMillis();
        byte[] signature = GenerateSignature(originalBytes, keys);
        System.out.println("Signature Generation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Time taken for Signature Generation: " + ((end - start) / 1000.0) + " seconds");

        System.out.println("Signature Validation started: ");
        start = System.currentTimeMillis();
        boolean isValidated = ValidateSignature(originalBytes, keys, signature);
        System.out.println("Signature Verified: " + isValidated);
        System.out.println("Signature Validation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Time taken for Signature Validation: " + ((end - start) / 1000.0) + " seconds");
    }

}
