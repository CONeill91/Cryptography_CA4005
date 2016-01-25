package assignment_one;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.BitSet;
import java.util.logging.Logger;

/**
 * Created by conor on 19/10/15.
 */
public class SymmetricFileEncryption {
    final static Logger logger = Logger.getLogger(SymmetricFileEncryption.class.getName());

    public static void main(String[] args) {

        final String filePath = "/home/conor/Fourth_Year_Notes/Crypto/Assignment_1/src/SymmetricFileEncryption.zip";
        final String password = "CC5t31m2ZjmOw0l";
        final String modulus = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
        final int exponent = 65537;
        byte[] pw = encodePassword(password);
        byte[] salt = generateRandom128BitValue();
        byte[] iv = generateRandom128BitValue();

        byte concat[] = new byte[salt.length + pw.length];
        // Concat PW & Salt
        System.arraycopy(salt, 0, concat, 0, salt.length);
        System.arraycopy(pw, 0, concat, salt.length, pw.length);

        try {
            // SHA-256 Hash concatenation 200 times
            byte[] hashedValue = sha256Digest(concat);
            logger.info("Encrypted Key Hex: " + bytesToHex(hashedValue));
            // Encrypt file using AES
            byte[] cipherText = encryptFile(filePath, hashedValue, iv);
            logger.info("Encrypted File Hex: " + bytesToHex(cipherText));
        } catch (NoSuchAlgorithmException e) {
            logger.info("Invalid hash algorithm");

        } catch (NoSuchPaddingException e) {
            logger.info("No such padding");

        } catch (IOException e) {
            logger.info("IOException: Unable to read file to byte array");

        } catch (InvalidAlgorithmParameterException e) {
            logger.info("Invalid param passed to Cipher.init()");

        } catch (BadPaddingException e) {
            logger.info("Bad Padding");

        } catch (IllegalBlockSizeException e) {
            logger.info("Illegal Block Size");

        } catch (InvalidKeyException e) {
            logger.info("Invalid Key used in AES Encryption");

        }

        BigInteger encryptedPassword = modularExponentiation(modulus,exponent,pw);
        byte [] encryptedPasswordBytes = encryptedPassword.toByteArray();
        logger.info("Salt Hex: " + bytesToHex(salt));
        logger.info("IV Hex: " + bytesToHex(iv));
        logger.info("Encrypted Password Hex: " + bytesToHex(encryptedPasswordBytes));


    }

    public static byte[] encodePassword(String password) {
        return password.getBytes(Charset.forName("UTF-8"));
    }

    public static byte[] generateRandom128BitValue() {
        SecureRandom random = new SecureRandom();
        // 16 bytes = 128 bits
        byte bytes[] = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] sha256Digest(byte[] byteArray) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 200; i++) {
            byteArray = digest.digest(byteArray);
        }
        return byteArray;
    }

    public static byte[] encryptFile(String filePath, byte[] hashedKey, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        Path path = Paths.get(filePath);
        byte[] targetFile = Files.readAllBytes(path);
        byte [] targetFilePadded = addPadding(targetFile);

        /*
            TODO : ** READ WHEN CORRECTING **
            Hacky way to increase allowed Key size for AES to 256 bits.
            Instead of downloading & replacing java standard library jars.
            By default Java only allows 128 bit keys.
        */
        try {
            Field field = Class.forName("javax.crypto.JceSecurity").
                    getDeclaredField("isRestricted");
            field.setAccessible(true);
            field.set(null, Boolean.FALSE);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        SecretKeySpec key = new SecretKeySpec(hashedKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(targetFilePadded);
    }

    public static byte[] addPadding(byte [] message){
        byte [] padding;
        if(message.length % 16 != 0){
            padding = new byte[16 - (message.length % 16)];
            padding[0] = padding[0] |= (1 << 7);
            byte concat[] = new byte[message.length + padding.length];
            System.arraycopy(message, 0, concat, 0, message.length);
            System.arraycopy(padding, 0, concat, message.length, padding.length);
            return concat;
        }
            padding = new byte[16];
            padding[0] = padding[0] |= (1 << 7);
            byte concat[] = new byte[message.length + padding.length];
            System.arraycopy(message, 0, concat, 0, message.length);
            System.arraycopy(padding, 0, concat, message.length, padding.length);
            return concat;
    }

    public static BigInteger modularExponentiation(String modulus, int exponent, byte [] password){
        BigInteger result = new BigInteger("1");
        BigInteger mod = new BigInteger(modulus,16);
        BigInteger pw = new BigInteger(password);
        String exponentBinRep = Integer.toBinaryString(exponent);

        for(int i = 0; i < exponentBinRep.length(); i++){
            if(exponentBinRep.charAt(i) == '1'){
                result = result.multiply(pw).mod(mod);
            }
            pw = pw.multiply(pw).mod(mod);
        }
        return result;
    }

    // For printing purposes.
    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

}
