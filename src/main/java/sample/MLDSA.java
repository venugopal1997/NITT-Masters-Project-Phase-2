package sample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

public class MLDSA {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\file900M.zip"));

        Long start, end;
        Long overall_start, overall_end;
        overall_start = System.currentTimeMillis();

        System.out.println("Key Generation started: ");
        start = System.currentTimeMillis();
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        kpg.initialize(DilithiumParameterSpec.dilithium5);
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("Key Generation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Time taken for Key Generation: " + ((end - start) / 1000.0) + " seconds");

        System.out.println("Signature Generation started: ");
        start = System.currentTimeMillis();
//        Signature sig = Signature.getInstance("ML-DSA");
        Signature sig = Signature.getInstance("Dilithium", "BCPQC");
        sig.initSign(kp.getPrivate());
        sig.update(originalBytes);
        byte[] signature = sig.sign();
        System.out.println("Signature Generation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Signature Length: " + signature.length);
        System.out.println("Time taken for Signature Generation: " + ((end - start) / 1000.0) + " seconds");

        System.out.println("Signature Validation started: ");
        start = System.currentTimeMillis();
        sig.initVerify(kp.getPublic());
        sig.update(originalBytes);
        boolean isVerified = sig.verify(signature);
        System.out.println("Signature Verified: " + isVerified);
        System.out.println("Signature Validation ended: ");
        end = System.currentTimeMillis();
        System.out.println("Signature Length: " + signature.length);
        System.out.println("Time taken for Signature Validation: " + ((end - start) / 1000.0) + " seconds");

        overall_end = System.currentTimeMillis();
        System.out.println("Overall Time taken: " + ((overall_end - overall_start) / 1000.0) + " seconds");
    }
}