package com.hanhuy.keepassj;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author pfnguyen
 */
public class Digests {
    public interface DigestProvider {
        public MessageDigest sha256();
        public MessageDigest sha512();
    }

    private static DigestProvider INSTANCE = new DigestProvider() {
        public MessageDigest sha256() {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
        public MessageDigest sha512() {
            try {
                return MessageDigest.getInstance("SHA-512");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    };

    public static byte[] sha256(byte[] data) {
        return getInstance().sha256().digest(data);
    }

    public static byte[] sha512(byte[] data) {
        return getInstance().sha512().digest(data);
    }

    public static DigestProvider getInstance() {
        return INSTANCE;
    }

    public static void setInstance(DigestProvider p) {
        INSTANCE = p;
    }
}
