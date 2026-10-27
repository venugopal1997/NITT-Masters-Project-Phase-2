package sample;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;

public class RSA {

    public static void GetTimestamp(String info){
        System.out.println(info + new Timestamp((new Date()).getTime()));
    }

    public static AsymmetricCipherKeyPair GenerateKeys() throws NoSuchAlgorithmException{
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters
                (
                        new BigInteger("10001", 16),//publicExponent 0x10001 in hexadecimal is equal to 65537 in decimal
                        SecureRandom.getInstance("SHA1PRNG"),//pseudorandom number generator
                        2048,//strength
                        80//certainty
                ));

        return generator.generateKeyPair();
    }

    public static byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey) throws Exception{
//	Source: http://www.cs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/engines/RSAEngine.html
        Security.addProvider(new BouncyCastleProvider());

        RSAEngine engine = new RSAEngine();
        engine.init(true, publicKey); //true if encrypt

        byte[] encryptedBytes = engine.processBlock(data, 0, data.length);

        return encryptedBytes;
    }

    public static byte[] Decrypt(byte[] encryptedBytes, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException{
//	Source: http://www.mysamplecode.com/2011/08/java-rsa-decrypt-string-using-bouncy.html

        Security.addProvider(new BouncyCastleProvider());

        AsymmetricBlockCipher engine = new RSAEngine();
        engine.init(false, privateKey); //false for decryption

        byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);

        return hexEncodedCipher;
    }

    public static void main(String[] args) throws Exception {
        byte[] originalBytes = Files.readAllBytes(Paths.get("F:\\TestFiles\\rsa-file200B.txt"));

        GetTimestamp("Key Pair Generation started: ");
        AsymmetricCipherKeyPair keyPair = GenerateKeys();
        GetTimestamp("Key Pair Generation ended: ");

        GetTimestamp("Encryption started: ");
        byte[] encryptedBytes = Encrypt(originalBytes, keyPair.getPublic());
        GetTimestamp("Encryption ended: ");

        GetTimestamp("Decryption started: ");
        byte[] decryptedBytes = Decrypt(encryptedBytes, keyPair.getPrivate());
//        String decryptedMessage = new String(decryptedBytes);
        GetTimestamp("Decryption ended: ");

        System.out.println("Original == Decrypted ? => " + Arrays.equals(originalBytes, decryptedBytes));
    }

}