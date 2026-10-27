package sample;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

public class ECDSA {

    public static byte[] GenerateSignature(byte[] originalBytes, KeyPair keys) throws SignatureException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(keys.getPrivate());
        ecdsaSign.update(originalBytes);
        byte[] signature = ecdsaSign.sign();
        return signature;
    }

    public static boolean ValidateSignature(byte[] originalBytes, KeyPair pair, byte[] signature) throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(pair.getPublic());
        ecdsaVerify.update(originalBytes);
        return ecdsaVerify.verify(signature);
    }

    public static KeyPair GenerateKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
//	Other named curves can be found in http://www.bouncycastle.org/wiki/display/JA1/Supported+Curves+%28ECDSA+and+ECGOST%29
//        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("B-571");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\file900M.zip"));

        Long start, end;
        Long overall_start, overall_end;
        overall_start = System.currentTimeMillis();

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

        overall_end = System.currentTimeMillis();
        System.out.println("Overall Time taken: " + ((overall_end - overall_start) / 1000.0) + " seconds");
    }
}
