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

/// <summary>
	/// Algorithms supported by <c>CryptoRandomStream</c>.
	/// </summary>
	enum CrsAlgorithm
	{
		/// <summary>
		/// Not supported.
		/// </summary>
		Null,

		/// <summary>
		/// A variant of the ARCFour algorithm (RC4 incompatible).
		/// </summary>
		ArcFourVariant,

		/// <summary>
		/// Salsa20 stream cipher algorithm.
		/// </summary>
		Salsa20,

		Count
	}

	/// <summary>
	/// A random stream class. The class is initialized using random
	/// bytes provided by the caller. The produced stream has random
	/// properties, but for the same seed always the same stream
	/// is produced, i.e. this class can be used as stream cipher.
	/// </summary>
	public class CryptoRandomStream
	{
		private CrsAlgorithm m_crsAlgorithm;

		private byte[] m_pbState = null;
		private byte m_i = 0;
		private byte m_j = 0;

		private Salsa20Cipher m_salsa20 = null;

		/// <summary>
		/// Construct a new cryptographically secure random stream object.
		/// </summary>
		/// <param name="genAlgorithm">Algorithm to use.</param>
		/// <param name="pbKey">Initialization key. Must not be <c>null</c> and
		/// must contain at least 1 byte.</param>
		/// <exception cref="System.IllegalArgumentException">Thrown if the
		/// <paramref name="pbKey" /> parameter is <c>null</c>.</exception>
		/// <exception cref="System.IllegalArgumentException">Thrown if the
		/// <paramref name="pbKey" /> parameter contains no bytes or the
		/// algorithm is unknown.</exception>
		public CryptoRandomStream(CrsAlgorithm genAlgorithm, byte[] pbKey)
		{
			m_crsAlgorithm = genAlgorithm;

			assert pbKey != null; if(pbKey == null) throw new IllegalArgumentException("pbKey");

			int uKeyLen = (int)pbKey.length;
			assert uKeyLen != 0; if(uKeyLen == 0) throw new IllegalArgumentException();

			if(genAlgorithm == CrsAlgorithm.ArcFourVariant)
			{
				// Fill the state linearly
				m_pbState = new byte[256];
				for(int w = 0; w < 256; ++w) m_pbState[w] = (byte)w;

					byte j = 0, t;
					int inxKey = 0;
					for(int w = 0; w < 256; ++w) // Key setup
					{
						j += (byte)(m_pbState[w] + pbKey[inxKey]);

						t = m_pbState[0]; // Swap entries
						m_pbState[0] = m_pbState[j];
						m_pbState[j] = t;

						++inxKey;
						if(inxKey >= uKeyLen) inxKey = 0;
					}

				GetRandomBytes(512); // Increases security, see cryptanalysis
			}
			else if(genAlgorithm == CrsAlgorithm.Salsa20)
			{
                try {
                    byte[] pbKey32 = Digests.sha256(pbKey);
                    byte[] pbIV = new byte[]{(byte) 0xE8, 0x30, 0x09, 0x4B,
                            (byte) 0x97, 0x20, 0x5D, 0x2A}; // Unique constant

                    m_salsa20 = new Salsa20Cipher(pbKey32, pbIV);
                } catch (Exception e) { throw new IllegalStateException(e); }
			}
			else // Unknown algorithm
			{
				assert false;
				throw new IllegalArgumentException();
			}
		}

		/// <summary>
		/// Get <paramref name="uRequestedCount" /> random bytes.
		/// </summary>
		/// <param name="uRequestedCount">Number of random bytes to retrieve.</param>
		/// <returns>Returns <paramref name="uRequestedCount" /> random bytes.</returns>
		public byte[] GetRandomBytes(int uRequestedCount)
		{
			if(uRequestedCount == 0) return new byte[0];

			byte[] pbRet = new byte[uRequestedCount];

			if(m_crsAlgorithm == CrsAlgorithm.ArcFourVariant)
			{
					for(int w = 0; w < uRequestedCount; ++w)
					{
						++m_i;
						m_j += m_pbState[m_i];

						byte t = m_pbState[m_i]; // Swap entries
						m_pbState[m_i] = m_pbState[m_j];
						m_pbState[m_j] = t;

						t = (byte)(m_pbState[m_i] + m_pbState[m_j]);
						pbRet[w] = m_pbState[t];
					}
			}
			else if(m_crsAlgorithm == CrsAlgorithm.Salsa20)
				m_salsa20.Encrypt(pbRet, pbRet.length, false);
			else { assert false; }

			return pbRet;
		}

		public long GetRandomUInt64()
		{
			byte[] pb = GetRandomBytes(8);

				return ((long)pb[0]) | ((long)pb[1] << 8) |
					((long)pb[2] << 16) | ((long)pb[3] << 24) |
					((long)pb[4] << 32) | ((long)pb[5] << 40) |
					((long)pb[6] << 48) | ((long)pb[7] << 56);
		}

	}
