package io.github.red050911.lib.simpleutils.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

/**
 * A class that represents a hash.
 * @since 1.0
 */
public class Hash implements Serializable {

    /**
     * The type of hash (the algorithm used)
     * @since 1.0
     */
    private final Type type;
    /**
     * The data of the hash (not containing salt)
     * @since 1.0
     */
    private final byte[] hashData;
    /**
     * The data of the salt (not containing hash)
     */
    private final byte[] saltData;
    /**
     * The hash with the first 16 bytes being salt
     * @since 1.0
     */
    private final byte[] combinedHashSalt;

    /**
     * The main constructor for a hash
     * @param type The algorithm to use
     * @param data The data to hash
     * @since 1.0
     */
    public Hash(Type type, String data) {
        this.type = type;
        switch(type) {
            case PBKDF2 -> this.combinedHashSalt = HashMethods.pbkdf2(data, HashMethods.genSalt());
            case PKCS5 -> this.combinedHashSalt = HashMethods.pkcs5(data, HashMethods.genSalt());
            case MD2 -> this.combinedHashSalt = HashMethods.md2(data, HashMethods.genSalt());
            case MD5 -> this.combinedHashSalt = HashMethods.md5(data, HashMethods.genSalt());
            case SHA1 -> this.combinedHashSalt = HashMethods.sha1(data, HashMethods.genSalt());
            case SHA256 -> this.combinedHashSalt = HashMethods.sha256(data, HashMethods.genSalt());
            case SHA384 -> this.combinedHashSalt = HashMethods.sha384(data, HashMethods.genSalt());
            case SHA512 -> this.combinedHashSalt = HashMethods.sha512(data, HashMethods.genSalt());
            case UNSALTED_MD2 -> this.combinedHashSalt = HashMethods.md2(data, new byte[]{});
            case UNSALTED_MD5 -> this.combinedHashSalt = HashMethods.md5(data, new byte[]{});
            case UNSALTED_SHA1 -> this.combinedHashSalt = HashMethods.sha1(data, new byte[]{});
            case UNSALTED_SHA256 -> this.combinedHashSalt = HashMethods.sha256(data, new byte[]{});
            case UNSALTED_SHA384 -> this.combinedHashSalt = HashMethods.sha384(data, new byte[]{});
            case UNSALTED_SHA512 -> this.combinedHashSalt = HashMethods.sha512(data, new byte[]{});
            default -> this.combinedHashSalt = new byte[]{};
        }
        if(type.name().toLowerCase(Locale.ROOT).startsWith("unsalted_")) {
            this.hashData = this.combinedHashSalt;
            this.saltData = null;
        } else {
            this.hashData = Arrays.copyOfRange(this.combinedHashSalt, 16, this.combinedHashSalt.length);
            this.saltData = Arrays.copyOfRange(this.combinedHashSalt, 0, 16);
        }
    }

    /**
     * Gets the algorithm used for the hash
     * @return The algorithm used for the hash
     * @since 1.0
     */
    public Type getType() {
        return type;
    }

    /**
     * Gets the hash data (not including salt)
     * @return The hash data
     * @since 1.0
     * @see #getHashDataBase64()
     */
    public byte[] getHashData() {
        return hashData;
    }

    /**
     * Gets the hash data in Base64 (as a String)
     * @return The hash data as a Base64 string
     * @see #getHashData()
     * @since 1.0
     */
    public String getHashDataBase64() {
        return Base64.getEncoder().encodeToString(getHashData());
    }

    /**
     * Gets the salt data (not including hash)
     * @return The salt data (or null if not applicable)
     * @see #getHashDataBase64()
     * @since 1.0
     */
    public byte[] getSaltData() {
        return saltData;
    }

    /**
     * Gets the salt data in Base64 (as a String)
     * @return The salt data as a Base64 string (or null if not applicable)
     * @see #getSaltData()
     * @since 1.0
     */
    public String getSaltDataBase64() {
        return getSaltData() != null ? Base64.getEncoder().encodeToString(getSaltData()) : null;
    }

    /**
     * Gets the hash data (first 16 bytes are salt if applicable)
     * Recommended for just getting the hash
     * @return The hash data
     * @see #getCombinedHashSaltBase64()
     * @since 1.0
     */
    public byte[] getCombinedHashSalt() {
        return combinedHashSalt;
    }

    /**
     * Gets the hash data (first 16 bytes are salt if applicable) as a Base64 string
     * Recommended for just getting the hash
     * @return The hash data as a Base64 string
     * @see #getCombinedHashSalt()
     * @since 1.0
     */
    public String getCombinedHashSaltBase64() {
        return Base64.getEncoder().encodeToString(getCombinedHashSalt());
    }

    /**
     * Returns true if this hash matches a string
     * @param otherData The string to check against
     * @return If the hash matches the string
     * @since 1.0
     */
    public boolean hashMatches(String otherData) {
        byte[] otherHashWithOurSalt;
        switch(this.type) {
            case PBKDF2 -> otherHashWithOurSalt = HashMethods.pbkdf2(otherData, this.saltData);
            case PKCS5 -> otherHashWithOurSalt = HashMethods.pkcs5(otherData, this.saltData);
            case MD2 -> otherHashWithOurSalt = HashMethods.md2(otherData, this.saltData);
            case MD5 -> otherHashWithOurSalt = HashMethods.md5(otherData, this.saltData);
            case SHA1 -> otherHashWithOurSalt = HashMethods.sha1(otherData, this.saltData);
            case SHA256 -> otherHashWithOurSalt = HashMethods.sha256(otherData, this.saltData);
            case SHA384 -> otherHashWithOurSalt = HashMethods.sha384(otherData, this.saltData);
            case SHA512 -> otherHashWithOurSalt = HashMethods.sha512(otherData, this.saltData);
            case UNSALTED_MD2 -> otherHashWithOurSalt = HashMethods.md2(otherData, new byte[]{});
            case UNSALTED_MD5 -> otherHashWithOurSalt = HashMethods.md5(otherData, new byte[]{});
            case UNSALTED_SHA1 -> otherHashWithOurSalt = HashMethods.sha1(otherData, new byte[]{});
            case UNSALTED_SHA256 -> otherHashWithOurSalt = HashMethods.sha256(otherData, new byte[]{});
            case UNSALTED_SHA384 -> otherHashWithOurSalt = HashMethods.sha384(otherData, new byte[]{});
            case UNSALTED_SHA512 -> otherHashWithOurSalt = HashMethods.sha512(otherData, new byte[]{});
            default -> otherHashWithOurSalt = new byte[]{};
        }
        String oursEncoded = getCombinedHashSaltBase64();
        String otherEncoded = Base64.getEncoder().encodeToString(otherHashWithOurSalt);
        return oursEncoded.equals(otherEncoded);
    }

    /**
     * One {@link Hash.Type} object represents a hashing method. By default, all of them will use salts except for ones prefixed with "UNSALTED_".
     * @since 1.0
     */
    public enum Type implements Serializable {

        /**
         * PBKDF2 hashing is the one out of this list that is recommended for password hashing.
         * This hash method must be salted.
         * @since 1.0
         */
        PBKDF2,
        /**
         * PKCS5 hashing is a hashing method that can be used for password hashing, however we recommend {@link #PBKDF2} instead.
         * This hash method must be salted.
         * @since 1.0
         */
        PKCS5,
        /**
         * MD2 hashing is not recommended, however is possible using SimpleUtils.
         * @since 1.0
         * @deprecated (in 1.0) Please use something like {@link #SHA256}
         */
        @Deprecated
        MD2,
        /**
         * MD5 hashing is not recommended, however is possible using SimpleUtils.
         * @since 1.0
         * @deprecated (in 1.0) MD5 is known to have hash collisions and should be avoided. Try {@link #SHA256}.
         */
        @Deprecated
        MD5,
        /**
         * SHA1 is a form of SHA that uses 160-bit hashes. We would recommend {@link #SHA256} instead.
         * @since 1.0
         */
        SHA1,
        /**
         * SHA256 is a form of SHA that uses 256-bit hashes. This is our recommended hash method for non-password data.
         * @since 1.0
         */
        SHA256,
        /**
         * SHA384 is a form of SHA similar to {@link #SHA512}, however it has a smaller hash size.
         * @since 1.0
         */
        SHA384,
        /**
         * SHA512 is a form of SHA that uses larger hashes and slower hashing. It should be used over {@link #SHA256} if collision-proofing is absolutely required.
         * Otherwise, SHA512 is a waste of CPU resources over {@link #SHA256}.
         * @since 1.0
         */
        SHA512,
        /**
         * MD2 hashing is not recommended, however is possible using SimpleUtils.
         * This is a version of MD2 that does not use salts.
         * @since 1.0
         * @deprecated (in 1.0) Please use something like {@link #SHA256}
         */
        @Deprecated
        UNSALTED_MD2,
        /**
         * MD5 hashing is not recommended, however is possible using SimpleUtils.
         * This is a version of MD5 that does not use salts.
         * @since 1.0
         * @deprecated (in 1.0) MD5 is known to have hash collisions and should be avoided. Try {@link #SHA256}.
         */
        @Deprecated
        UNSALTED_MD5,
        /**
         * SHA1 is a form of SHA that uses 160-bit hashes. We would recommend {@link #SHA256} instead.
         * This is a version of SHA1 that does not use salts.
         * @since 1.0
         */
        UNSALTED_SHA1,
        /**
         * SHA256 is a form of SHA that uses 256-bit hashes. This is our recommended hash method for non-password data.
         * This is a version of SHA256 that does not use salts.
         * @since 1.0
         */
        UNSALTED_SHA256,
        /**
         * SHA384 is a form of SHA similar to {@link #SHA512}, however it has a smaller hash size.
         * This is a version of SHA384 that does not use salts.
         * @since 1.0
         */
        UNSALTED_SHA384,
        /**
         * SHA512 is a form of SHA that uses larger hashes and slower hashing. It should be used over {@link #SHA256} if collision-proofing is absolutely required.
         * Otherwise, SHA512 is a waste of CPU resources over {@link #SHA256}.
         * This is a version of SHA384 that does not use salts.
         * @since 1.0
         */
        UNSALTED_SHA512

    }

    /**
     * No javadoc will be available in this class due to it being an internal, private class. This class performs hashing operations.
     * @since 1.0
     */
    private static class HashMethods {

        private static byte[] pbkdf2(String data, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(data.toCharArray(), salt, 65536, 128);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                byte[] hashData = keyFactory.generateSecret(spec).getEncoded();
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] pkcs5(String data, byte[] salt) {
            try {
                PBEKeySpec spec = new PBEKeySpec(data.toCharArray(), salt, 1000, 512);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
                byte[] hashData = keyFactory.generateSecret(spec).getEncoded();
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] md2(String data, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("MD2");
                md.update(salt);
                byte[] hashData = md.digest(data.getBytes(StandardCharsets.UTF_8));
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] md5(String data, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(salt);
                byte[] hashData = md.digest(data.getBytes(StandardCharsets.UTF_8));
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] sha1(String data, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(salt);
                byte[] hashData = md.digest(data.getBytes(StandardCharsets.UTF_8));
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }
        private static byte[] sha256(String data, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(salt);
                byte[] hashData = md.digest(data.getBytes(StandardCharsets.UTF_8));
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] sha384(String data, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-384");
                md.update(salt);
                byte[] hashData = md.digest(data.getBytes(StandardCharsets.UTF_8));
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] sha512(String data, byte[] salt) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                md.update(salt);
                byte[] hashData = md.digest(data.getBytes(StandardCharsets.UTF_8));
                return joinByteArrays(salt, hashData);
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

        private static byte[] joinByteArrays(byte[] arrayOne, byte[] arrayTwo) {
            byte[] rV = new byte[arrayOne.length + arrayTwo.length];
            int index = 0;
            for(byte b : arrayOne) {
                rV[index] = b;
                index++;
            }
            for(byte b : arrayTwo) {
                rV[index] = b;
                index++;
            }
            return rV;
        }

        private static byte[] genSalt() {
            try {
                SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
                byte[] salt = new byte[16];
                rand.nextBytes(salt);
                return salt;
            } catch(Exception ex) {
                return new byte[]{};
            }
        }

    }

}
