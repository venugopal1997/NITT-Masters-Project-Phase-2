package sample;

import jRAPL.*;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.*;

//@State(Scope.Thread)
//@BenchmarkMode(Mode.AverageTime)
//@Measurement(iterations = 1)
//@Warmup(iterations = 1)
//@OutputTimeUnit(TimeUnit.MILLISECONDS)
//@Fork(value = 1)
public class MLKEM {

    private static final String KEM_ALGORITHM = "Kyber";
    private static final AlgorithmParameterSpec KEM_PARAMETER_SPEC = KyberParameterSpec.kyber1024;
    private static final String PROVIDER = "BCPQC";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final Integer ENCRYPTION_ALGORITHM_STRENGTH = 256;
    private static final String MODE_PADDING = "AES/ECB/PKCS5Padding";

    public static byte[] encrypt(byte[] plainTextBytes, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainTextBytes);
        return encryptedBytes;
    }

    public static byte[] decrypt(byte[] encryptedBytes, byte[] key) throws Exception {
        System.out.println(key.length);
        SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return decryptedBytes;
    }

    private static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(KEM_PARAMETER_SPEC, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKeyWithEncapsulation generateSecretKeySender(PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
//        KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(publicKey, "Secret");
        KEMGenerateSpec kemGenerateSpec =
                new KEMGenerateSpec.Builder(publicKey, ENCRYPTION_ALGORITHM, ENCRYPTION_ALGORITHM_STRENGTH).build();
        keyGenerator.init(kemGenerateSpec);
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }

    private static SecretKeyWithEncapsulation generateSecretKeyReciever(PrivateKey privateKey, byte[] encapsulation)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER);
//        KEMExtractSpec kemExtractSpec = new KEMExtractSpec(privateKey, encapsulation, "Secret");
        KEMExtractSpec kemExtractSpec =
                new KEMExtractSpec.Builder(privateKey, encapsulation, ENCRYPTION_ALGORITHM, ENCRYPTION_ALGORITHM_STRENGTH).build();
        keyGenerator.init(kemExtractSpec);

        return (SecretKeyWithEncapsulation)keyGenerator.generateKey();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\file900M.zip"));

        Long start, end;
        start = System.currentTimeMillis();

//        SyncEnergyMonitor m = new SyncEnergyMonitor();
//        m.activate();
//        EnergyStats before = m.getSample();

        // Alice
        KeyPair keyPair = generateKeyPair();
        System.out.println("KEM Algorithm: " + keyPair.getPublic().getAlgorithm());
        System.out.println("Public Key length: " + keyPair.getPublic().getEncoded().length);
        System.out.println("Private Key length: " + keyPair.getPrivate().getEncoded().length);
        // Alice send the Public Key to Bob

        // Bob
        SecretKeyWithEncapsulation initKeyWithEnc = generateSecretKeySender(keyPair.getPublic());
        byte[] encapsulation = initKeyWithEnc.getEncapsulation();
        System.out.println("Shared Secret created by Sender: " + Hex.toHexString(initKeyWithEnc.getEncoded()));
        System.out.println("Length of encapsulated shared secret: " + encapsulation.length);
        byte[] encryptedBytes = encrypt(originalBytes, initKeyWithEnc.getEncoded());
        // Bob send the Encapsulation to Alice

        // Alice
        SecretKeyWithEncapsulation recKeyWithEnc = generateSecretKeyReciever(keyPair.getPrivate(), encapsulation);
        System.out.println("Shared Secret decapsulated by Receiver: " + Hex.toHexString(recKeyWithEnc.getEncoded()));
        byte[] decryptedBytes = decrypt(encryptedBytes, recKeyWithEnc.getEncoded());

//        EnergyStats after = m.getSample();
//        EnergyDiff diff = EnergyDiff.between(before, after);
//        System.out.println("Energy taken: " + diff + " joules");
//        m.deactivate();

        end = System.currentTimeMillis();
        System.out.println("Time taken: " + ((end - start) / 1000.0) + " seconds");

        System.out.println("Original Length: " + originalBytes.length);
        System.out.println("Encrypted Length: " + encryptedBytes.length);
        System.out.println("Decrypted Length: " + decryptedBytes.length);
        System.out.println("Original == Decrypted ? => " + Arrays.equals(originalBytes, decryptedBytes));
    }
}