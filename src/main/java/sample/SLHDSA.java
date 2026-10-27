package sample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

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

public class SLHDSA {

    public static byte[] GenerateSignature(byte[] originalBytes, KeyPair keys) throws SignatureException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sign = Signature.getInstance("SPHINCSPLUS", "BCPQC");
        sign.initSign(keys.getPrivate());
        sign.update(originalBytes);
        byte[] signature = sign.sign();
        return signature;
    }

    public static boolean ValidateSignature(byte[] originalBytes, KeyPair pair, byte[] signature) throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature verify = Signature.getInstance("SPHINCSPLUS", "BCPQC");
        verify.initVerify(pair.getPublic());
        verify.update(originalBytes);
        return verify.verify(signature);
    }

    public static KeyPair GenerateKeys(SPHINCSPlusParameterSpec sPHINCSPlusParameterSpec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("SPHINCSPLUS", "BCPQC");
        g.initialize(sPHINCSPlusParameterSpec);
        return g.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\file900M.zip"));

        Long start, end;
        Long overall_start, overall_end;
        overall_start = System.currentTimeMillis();

        System.out.println("Key Generation started: ");
        start = System.currentTimeMillis();
        KeyPair keys = GenerateKeys(SPHINCSPlusParameterSpec.shake_256f);
        System.out.println("Key Generation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Time taken for Key Generation: " + ((end - start) / 1000.0) + " seconds");

        System.out.println("Signature Generation started: ");
        start = System.currentTimeMillis();
        byte[] signature = GenerateSignature(originalBytes, keys);
        System.out.println("Signature Generation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Signature Length: " + signature.length);
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