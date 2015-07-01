package com.hanhuy.keepassj;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * @author pfnguyen
 */
public class AesEngines {
    public static BlockCipher createAesEngine() {
        return factory.createAesEngine();
    }

    public interface AesEngineFactory {
        BlockCipher createAesEngine();
    }

    private static AesEngineFactory factory = new AesEngineFactory() {
        @Override
        public BlockCipher createAesEngine() {
            return new AESEngine();
        }
    };

    public static void setAesEngineFactory(AesEngineFactory factory) {
        AesEngines.factory = factory;
    }

    public interface KeyTransformer {
        public boolean transformKey(byte[] key, byte[] seed, long rounds);
    }

    public static boolean transformKey(byte[] key, byte[] seed, long rounds) {
        return keyTransformer.transformKey(key, seed, rounds);
    }

    public static void setKeyTransformer(KeyTransformer transformer) {
        keyTransformer = transformer;
    }

    private static KeyTransformer keyTransformer = new KeyTransformer() {
        @Override
        public boolean transformKey(byte[] key, byte[] seed, long rounds) {
            byte[] pbIV = new byte[16];
            Arrays.fill(pbIV, (byte) 0);

            try {
                BlockCipher engine = AesEngines.createAesEngine();
                engine.init(true, new KeyParameter(seed));
                if (engine.getBlockSize() != (128 / 8)) // AES block size
                {
                    assert false;
                    throw new RuntimeException();
                }

//                IvParameterSpec ivspec = new IvParameterSpec(pbIV);
//                SecretKeySpec key = new SecretKeySpec(pbKeySeed32, "AES");
//                c.init(Cipher.ENCRYPT_MODE, key, ivspec);

                for (long i = 0; i < rounds; ++i) {
                    engine.processBlock(key, 0, key, 0);
                    engine.processBlock(key, 16, key, 16);
                }
//                engine.doFinal();
            } catch (Exception e) { throw new RuntimeException(e); }

            return true;
        }
    };
}
