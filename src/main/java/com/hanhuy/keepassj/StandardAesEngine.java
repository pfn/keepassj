package com.hanhuy.keepassj;
/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2014 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.InputStream;
import java.io.OutputStream;

/// <summary>
	/// Standard AES cipher implementation.
	/// </summary>
	public class StandardAesEngine implements ICipherEngine
	{
//		private final static CipherMode m_rCipherMode = CipherMode.CBC;
//		private final static PaddingMode m_rCipherPadding = PaddingMode.PKCS7;

		private static PwUuid m_uuidAes = null;

		/// <summary>
		/// UUID of the cipher engine. This ID uniquely identifies the
		/// AES engine. Must not be used by other ciphers.
		/// </summary>
		public static PwUuid getAesUuid()
		{
				if(m_uuidAes == null)
				{
					m_uuidAes = new PwUuid(new byte[]{
						0x31, (byte)0xC1, (byte)0xF2, (byte)0xE6, (byte)0xBF, 0x71, 0x43, 0x50,
						(byte)0xBE, 0x58, 0x05, 0x21, 0x6A, (byte)0xFC, 0x5A, (byte)0xFF });
				}

				return m_uuidAes;
		}

		/// <summary>
		/// Get the UUID of this cipher engine as <c>PwUuid</c> object.
		/// </summary>
		public PwUuid getCipherUuid()
		{
			return StandardAesEngine.getAesUuid();
		}

		/// <summary>
		/// Get a displayable name describing this cipher engine.
		/// </summary>
		public String getDisplayName() { return "AES"; }

		private static InputStream CreateInputStream(InputStream s, boolean bEncrypt, byte[] pbKey, byte[] pbIV)
		{

			byte[] pbLocalIV = new byte[16];
			System.arraycopy(pbIV, 0, pbLocalIV, 0, 16);

			byte[] pbLocalKey = new byte[32];
			System.arraycopy(pbKey, 0, pbLocalKey, 0, 32);

            try {
//                Cipher r = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                IvParameterSpec ivspec = new IvParameterSpec(pbLocalIV);
//                SecretKeySpec keyspec = new SecretKeySpec(pbLocalKey, "AES");
//                r.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

                BlockCipher aes = AesEngines.createAesEngine();
                KeyParameter key = new KeyParameter(pbLocalKey);
                ParametersWithIV iv = new ParametersWithIV(key, pbLocalIV);
                BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(aes));
                cipher.init(false, iv);

                return new CipherInputStream(s, cipher);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
		}
        private static OutputStream CreateOutputStream(OutputStream s, boolean bEncrypt, byte[] pbKey, byte[] pbIV)
        {

            byte[] pbLocalIV = new byte[16];
            System.arraycopy(pbIV, 0, pbLocalIV, 0, 16);

            byte[] pbLocalKey = new byte[32];
            System.arraycopy(pbKey, 0, pbLocalKey, 0, 32);

            try {
                BlockCipher aes = AesEngines.createAesEngine();
                KeyParameter key = new KeyParameter(pbLocalKey);
                ParametersWithIV iv = new ParametersWithIV(key, pbLocalIV);
                BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(aes));

                cipher.init(true, iv);
//                Cipher r = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                IvParameterSpec ivspec = new IvParameterSpec(pbLocalIV);
//                SecretKeySpec keyspec = new SecretKeySpec(pbLocalKey, "AES");
//                r.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);

                return new CipherOutputStream(s, cipher);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }


		public OutputStream EncryptStream(OutputStream sPlainText, byte[] pbKey, byte[] pbIV)
		{
			return StandardAesEngine.CreateOutputStream(sPlainText, true, pbKey, pbIV);
		}

		public InputStream DecryptStream(InputStream sEncrypted, byte[] pbKey, byte[] pbIV)
		{
			return StandardAesEngine.CreateInputStream(sEncrypted, false, pbKey, pbIV);
		}
	}
