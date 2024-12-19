package com.example.crypto;



import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;



import javax.crypto.Cipher;

import javax.crypto.KeyGenerator;

import javax.crypto.SecretKey;

import java.security.*;

import java.util.Base64;

import javax.ws.rs.*;

import javax.ws.rs.core.MediaType;

import javax.ws.rs.core.Response;



@Path("/crypto")

public class CryptoAPI {



    static {

        Security.addProvider(new BouncyCastleProvider());

        Security.addProvider(new BouncyCastlePQCProvider());

    }



    public enum Operation {

        ENCRYPT, DECRYPT, HASH, GENERATE_KEY

    }



    public enum AlgorithmType {

        SYMMETRIC, ASYMMETRIC, POST_QUANTUM, MESSAGE_DIGEST

    }



    @POST

    @Path("/operation")

    @Produces(MediaType.APPLICATION_JSON)

    @Consumes(MediaType.APPLICATION_JSON)

    public Response performCryptoOperation(@QueryParam("operation") Operation operation,

                                            @QueryParam("algorithm") String algorithm,

                                            @QueryParam("data") String data,

                                            @QueryParam("key") String keyBase64,

                                            @QueryParam("keyType") String keyType) {

        try {

            if (operation == Operation.HASH) {

                return Response.ok(hash(algorithm, data)).build();

            } else if (operation == Operation.ENCRYPT || operation == Operation.DECRYPT) {

                Key key = decodeKey(keyBase64, keyType, algorithm);

                String result = performOperation(operation, algorithm, data, key);

                return Response.ok(result).build();

            } else {

                throw new IllegalArgumentException("Invalid operation for this endpoint.");

            }

        } catch (Exception e) {

            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();

        }

    }



    @POST

    @Path("/generateKey")

    @Produces(MediaType.APPLICATION_JSON)

    @Consumes(MediaType.APPLICATION_JSON)

    public Response generateKey(@QueryParam("algorithm") String algorithm,

                                 @QueryParam("type") AlgorithmType type,

                                 @QueryParam("keySize") int keySize) {

        try {

            Key key = performKeyGeneration(Operation.GENERATE_KEY, algorithm, type, keySize);

            return Response.ok(Base64.getEncoder().encodeToString(key.getEncoded())).build();

        } catch (Exception e) {

            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();

        }

    }



    private static String performOperation(Operation operation, String algorithm, String data, Key key) throws Exception {

        switch (operation) {

            case ENCRYPT:

                return encrypt(algorithm, data, key);

            case DECRYPT:

                return decrypt(algorithm, data, key);

            default:

                throw new IllegalArgumentException("Invalid operation for this method. Use ENCRYPT or DECRYPT.");

        }

    }



    private static String hash(String algorithm, String data) throws Exception {

        MessageDigest digest = MessageDigest.getInstance(algorithm, "BC");

        byte[] hashedData = digest.digest(data.getBytes());

        return Base64.getEncoder().encodeToString(hashedData);

    }



    private static Key performKeyGeneration(Operation operation, String algorithm, AlgorithmType type, int keySize) throws Exception {

        if (operation != Operation.GENERATE_KEY) {

            throw new IllegalArgumentException("Invalid operation for this method. Use GENERATE_KEY.");

        }



        switch (type) {

            case SYMMETRIC:

                return generateSymmetricKey(algorithm, keySize);

            case ASYMMETRIC:

                return generateKeyPair(algorithm, keySize).getPrivate();

            case POST_QUANTUM:

                return generatePostQuantumKeyPair(algorithm).getPrivate();

            default:

                throw new IllegalArgumentException("Invalid algorithm type.");

        }

    }



    private static String encrypt(String algorithm, String data, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm, "BC");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(encryptedData);

    }



    private static String decrypt(String algorithm, String encryptedData, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm, "BC");

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

        return new String(decryptedData);

    }



    private static KeyPair generateKeyPair(String algorithm, int keySize) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, "BC");

        keyGen.initialize(keySize);

        return keyGen.generateKeyPair();

    }



    private static SecretKey generateSymmetricKey(String algorithm, int keySize) throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, "BC");

        keyGen.init(keySize);

        return keyGen.generateKey();

    }



    private static KeyPair generatePostQuantumKeyPair(String algorithm) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, "BCPQC");

        return keyGen.generateKeyPair();

    }



    private static Key decodeKey(String keyBase64, String keyType, String algorithm) throws Exception {

        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);

        switch (keyType) {

            case "public":

                KeyFactory keyFactory = KeyFactory.getInstance(algorithm, "BC");

                return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));

            case "private":

                keyFactory = KeyFactory.getInstance(algorithm, "BC");

                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

            case "secret":

                return new SecretKeySpec(keyBytes, algorithm);

            default:

                throw new IllegalArgumentException("Invalid key type: " + keyType);

        }

    }

}