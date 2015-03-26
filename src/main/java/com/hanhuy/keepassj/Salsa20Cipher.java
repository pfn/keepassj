package com.hanhuy.keepassj;

import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;
import static com.hanhuy.keepassj.MemUtil.bint;

public class Salsa20Cipher
	{
        private final Salsa20Engine engine;
		public Salsa20Cipher(byte[] pbKey32, byte[] pbIV8)
		{
            engine = new Salsa20Engine();
            KeyParameter key = new KeyParameter(pbKey32);
            ParametersWithIV iv = new ParametersWithIV(key, pbIV8);
            engine.init(true, iv);
		}

		public void Dispose()
		{
            engine.reset();
		}

		public void Encrypt(byte[] m, int nByteCount, boolean bXor)
		{
            engine.processBytes(m, 0, nByteCount, m, 0);
		}
	}
