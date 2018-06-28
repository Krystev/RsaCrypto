package com.inveitix.cryptito;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 * The main RsaCipher API for encryption and decryption of byte arrays.
 */
public class RsaCipher
{
    private static final String TAG = RsaCipher.class.getSimpleName();
    private static final String PREFIX_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String SUFFIX_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String PREFIX_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String SUFFIX_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private final RsaContext mContext;

    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;
    private byte[] mEncryptedBytes, mDecryptedBytes;
    private Cipher mEncryptCipher, decryptCipher;
    private String mEncryptedData, mDecryptedData;
    private KeyFactory mKeyFactory;
    private String mKeyStoreAlias;

    /**
     * Initializes a new {@code RsaCipher} object for encryption and decryption. See
     * {@link com.inveitix.cryptito.RsaContext} for an explanation of options.
     *
     * @param context an {@link com.inveitix.cryptito.RsaContext}
     */
    public RsaCipher(RsaContext context, String keyStoreAlias)
    {
        mKeyStoreAlias = keyStoreAlias;
        if (context == null ||
                context.getAlgorithm() == null ||
                context.getMode() == null ||
                context.getPadding() == null ||
                context.getKeyLength() == null) {

            throw new IllegalArgumentException("Context, algorithm, mode, or padding is null");
        }

        this.mContext = context;

        try {
            mEncryptCipher = Cipher.getInstance(mContext.getAlgorithm() + "/" + mContext.getMode()
                    + "/" + mContext.getPadding());
            decryptCipher = Cipher.getInstance(mContext.getAlgorithm() + "/" + mContext.getMode()
                    + "/" + mContext.getPadding());
            mKeyFactory = KeyFactory.getInstance(mContext.getAlgorithm().toString());
        }
        catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        generateKeyPair(context.getAlgorithm(), context.getKeyLength(), keyStoreAlias);
    }

    /**
     * Generate KeyPair for RSA keys
     *
     * @param algorithm     Set RsaContext.Algorithm
     * @param keyLength     Set key size
     * @param keyStoreAlias Your key store alias name
     */
    private void generateKeyPair(RsaContext.Algorithm algorithm, RsaContext.KeyLength keyLength, String keyStoreAlias)
    {
        if (algorithm == null || keyLength == null) {
            throw new IllegalArgumentException("Algorithm or key length is null");
        }


        try {
            KeyStore mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            mKeyStore.load(null);
            if (mKeyStore.containsAlias(keyStoreAlias)) {
                return;
            }

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder
                    (keyStoreAlias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setKeySize(keyLength.bits())
                    .build();

            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.toString(), ANDROID_KEY_STORE);
            generator.initialize(spec);
            KeyPair keyPair = generator.generateKeyPair();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private KeyStore.Entry getKeyEntry(String keyStoreAlias)
    {
        generateKeyPair(mContext.getAlgorithm(), mContext.getKeyLength(), keyStoreAlias);
        KeyStore mKeyStore;
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            mKeyStore.load(null);
            return mKeyStore.getEntry(keyStoreAlias, null);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey getPublicKey()
    {
        if (mPublicKey == null) {
            KeyStore.Entry privateKeyEntry = getKeyEntry(mKeyStoreAlias);
            if (!(privateKeyEntry instanceof KeyStore.PrivateKeyEntry)) {

                return null;
            }
            mPublicKey = ((KeyStore.PrivateKeyEntry) privateKeyEntry).getCertificate().getPublicKey();
        }

        return mPublicKey;
    }

    public PrivateKey getPrivateKey()
    {
        if (mPrivateKey == null) {
            KeyStore.Entry privateKeyEntry = getKeyEntry(mKeyStoreAlias);
            if (!(privateKeyEntry instanceof KeyStore.PrivateKeyEntry)) {

                return null;
            }

            mPrivateKey = ((KeyStore.PrivateKeyEntry) privateKeyEntry).getPrivateKey();
        }
        return mPrivateKey;
    }

    /**
     * Set private key from String
     *
     * @param privateKey Private key as String
     */
    public void setPrivateKey(String privateKey)
    {
        this.mPrivateKey = stringToPrivateKey(privateKey);
    }

    /**
     * Set Public key from String
     *
     * @param publicKey Public key as String
     */
    public void setPublicKey(String publicKey)
    {
        this.mPublicKey = stringToPublicKey(publicKey);
    }

    /**
     * Encrypt String data using public key
     *
     * @param data String data to be encrypted
     * @return Encrypted data as String
     */
    public String encryptByPublicKey(String data)
    {
        ByteArrayOutputStream outputStream;
        try {
            mEncryptCipher.init(Cipher.ENCRYPT_MODE, getPublicKey());

            outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, mEncryptCipher);
            cipherOutputStream.write(data.getBytes());
            cipherOutputStream.close();
            mEncryptedBytes = outputStream.toByteArray();
            mEncryptedData = Base64.encodeToString(mEncryptedBytes, Base64.DEFAULT);
            return mEncryptedData;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Encrypt String data using private key
     *
     * @param data String data to be encrypted
     * @return Encrypted data as String
     */
    public String encryptByPrivateKey(String data)
    {
        ByteArrayOutputStream outputStream;
        try {
            mEncryptCipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());

            outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, mEncryptCipher);
            cipherOutputStream.write(data.getBytes());
            cipherOutputStream.close();
            mEncryptedBytes = outputStream.toByteArray();
            mEncryptedData = Base64.encodeToString(mEncryptedBytes, Base64.DEFAULT);
            return mEncryptedData;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt data encrypted with public key, using private key for decryption
     *
     * @param data Encrypted data
     * @return Decrypted data
     */
    public String decryptByPrivateKey(String data)
    {
        byte[] encryptedBytes = Base64.decode(data, Base64.DEFAULT);


        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(encryptedBytes), decryptCipher);

            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            mDecryptedBytes = new byte[values.size()];
            for (int i = 0; i < mDecryptedBytes.length; i++) {
                mDecryptedBytes[i] = values.get(i);
            }
            mDecryptedData = new String(mDecryptedBytes);
            return mDecryptedData;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt data encrypted with private key, using PublicKey for decryption
     *
     * @param data Encrypted data
     * @return Decrypted data
     */
    public String decryptByPublicKey(String data)
    {
        byte[] encryptedBytes = Base64.decode(data, Base64.DEFAULT);


        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, getPublicKey());
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(encryptedBytes), decryptCipher);

            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            mDecryptedBytes = new byte[values.size()];
            for (int i = 0; i < mDecryptedBytes.length; i++) {
                mDecryptedBytes[i] = values.get(i);
            }
            mDecryptedData = new String(mDecryptedBytes);
            return mDecryptedData;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Generate public key from string
     *
     * @param publicKeyString Public key as String
     * @return PublicKey
     */
    private PublicKey stringToPublicKey(String publicKeyString)
    {
        try {
            if (publicKeyString.contains(PREFIX_PUBLIC_KEY) || publicKeyString.contains(SUFFIX_PUBLIC_KEY)) {
                publicKeyString = publicKeyString.replace(PREFIX_PUBLIC_KEY, "").replace(SUFFIX_PUBLIC_KEY, "");
            }
            byte[] keyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

            return mKeyFactory.generatePublic(spec);
        }
        catch (InvalidKeySpecException e) {
            Log.e(TAG, "Invalid Key Specifications for RSA encrypting", e);
            return null;
        }
    }

    /**
     * Generate Private Key from string
     *
     * @param privateKeyString Private key as String
     * @return PrivateKey
     */
    private PrivateKey stringToPrivateKey(String privateKeyString)
    {
        try {
            if (privateKeyString.contains(PREFIX_PRIVATE_KEY) || privateKeyString.contains(SUFFIX_PRIVATE_KEY)) {
                privateKeyString = privateKeyString.replace(PREFIX_PRIVATE_KEY, "").replace(SUFFIX_PRIVATE_KEY, "");
            }
            byte[] keyBytes = Base64.decode(privateKeyString, Base64.DEFAULT);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

            return mKeyFactory.generatePrivate(spec);
        }
        catch (InvalidKeySpecException e) {
            Log.e(TAG, "Invalid Key Specifications for RSA encrypting", e);
            return null;
        }
    }
}
