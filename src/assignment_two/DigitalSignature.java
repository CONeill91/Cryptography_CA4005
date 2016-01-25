package assignment_two;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.logging.Logger;

/**
 * Created by conor on 09/11/15.
 * Submission : 30/11/15
 */
public class DigitalSignature {
    final static Logger logger = Logger.getLogger(DigitalSignature.class.getName());

    public static void main(String [] args) {
        // TODO : Check Hex strings before submission
        final String PRIME_MODULUS = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
        final String GENERATOR = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
        // TODO : Change to zip of source file.
        final String filePath = "/home/conor/Fourth_Year_Notes/Crypto/Assignment_2/src/DigitalSignature.java";

        BigInteger secretKey = generateRandomKey(PRIME_MODULUS);
        BigInteger publicKey = modularExp(GENERATOR, PRIME_MODULUS, secretKey);

        logger.info(bytesToHex(publicKey.toByteArray()));

        BigInteger k = chooseRandomValue(PRIME_MODULUS);
        BigInteger r = modularExp(GENERATOR, PRIME_MODULUS, k);
        try {
            BigInteger bracketValue = calculateBrackets(filePath, secretKey,r);
        } catch (IOException e) {
            logger.info("Error: No such file found");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            logger.info("Error: No such algorithm found(Hash)");
            e.printStackTrace();
        }
    }
    // TODO Check if the subtraction is necessary w/ Geoff
    public static BigInteger generateRandomKey(String pModHexString){
        Random rand = new Random();
        BigInteger upperLimit = new BigInteger(pModHexString,16).subtract(new BigInteger("1"));
        BigInteger result;
        do {
            result = new BigInteger(upperLimit.bitLength(), rand).add(new BigInteger("2"));
        } while (result.compareTo(upperLimit) >= 0);

        return result;
    }

    public static BigInteger modularExp(String generatorHexString, String primeModulusHexString, BigInteger exponent){
        BigInteger gen = new BigInteger(generatorHexString,16);
        BigInteger pModulus = new BigInteger(primeModulusHexString,16);
        gen = gen.modPow(exponent,pModulus);
        return gen;

    }
    // Choose random value for K
    public static BigInteger chooseRandomValue(String pModHexString){
        Random rand = new Random();
        BigInteger upperLimit = new BigInteger(pModHexString,16);
        BigInteger result;
        do {
            result = new BigInteger(upperLimit.bitLength(), rand).add(new BigInteger("1"));
        } while ((result.compareTo(upperLimit) >= 0));

        if(!gcd(result,upperLimit).equals(new BigInteger("1"))){
            chooseRandomValue(pModHexString);
        }
        return result;
    }

    // Return greatest common divisor(GCD) of two BigInteger objects
    public static BigInteger gcd(BigInteger a, BigInteger b){
        if (a.equals(new BigInteger("0"))){
            return b;
        }
        while(!b.equals(new BigInteger("0"))){
            if(a.compareTo(b) == 1){
               a = a.subtract(b);
            }
            else{
                b = b.subtract(a);
            }
        }
        return a;
    }

    public static BigInteger hashFunction(String filePath) throws IOException,NoSuchAlgorithmException{
        Path path = Paths.get(filePath);
        byte[] targetFile = Files.readAllBytes(path);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        targetFile = digest.digest(targetFile);
        return new BigInteger(targetFile);
    }

    public static BigInteger calculateBrackets(String filePath,BigInteger x, BigInteger r) throws IOException,NoSuchAlgorithmException{
        BigInteger hash = hashFunction(filePath);
        hash = hash.subtract(x.multiply(r));
        return hash;
    }

    /*public static BigInteger xgcd(BigInteger a, BigInteger b){

    }*/

    // For printing purposes.
    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }



}
