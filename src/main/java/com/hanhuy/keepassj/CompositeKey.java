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

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/// <summary>
	/// Represents a key. A key can be build up using several user key data sources
	/// like a password, a key file, the currently logged on user credentials,
	/// the current computer ID, etc.
	/// </summary>
	public class CompositeKey
	{
		private List<IUserKey> m_vUserKeys = new ArrayList<IUserKey>();

		/// <summary>
		/// List of all user keys contained in the current composite key.
		/// </summary>
		public Iterable<IUserKey> getUserKeys()
		{
			return m_vUserKeys;
		}

		public int getUserKeyCount()
		{
			return m_vUserKeys.size();
		}

		/// <summary>
		/// Construct a new, empty key object.
		/// </summary>
		public CompositeKey()
		{
		}

		// /// <summary>
		// /// Deconstructor, clears up the key.
		// /// </summary>
		// ~CompositeKey()
		// {
		//	Clear();
		// }

		// /// <summary>
		// /// Clears the key. This function also erases all previously stored
		// /// user key data objects.
		// /// </summary>
		// public void Clear()
		// {
		//	foreach(IUserKey pKey in m_vUserKeys)
		//		pKey.Clear();
		//	m_vUserKeys.Clear();
		// }

		/// <summary>
		/// Add a user key.
		/// </summary>
		/// <param name="pKey">User key to add.</param>
		public void AddUserKey(IUserKey pKey)
		{
			assert pKey != null; if(pKey == null) throw new IllegalArgumentException("pKey");

			m_vUserKeys.add(pKey);
		}

		/// <summary>
		/// Remove a user key.
		/// </summary>
		/// <param name="pKey">User key to remove.</param>
		/// <returns>Returns <c>true</c> if the key was removed successfully.</returns>
		public boolean RemoveUserKey(IUserKey pKey)
		{
			assert pKey != null; if(pKey == null) throw new IllegalArgumentException("pKey");

			assert m_vUserKeys.indexOf(pKey) >= 0;
			return m_vUserKeys.remove(pKey);
		}

		/// <summary>
		/// Test whether the composite key contains a specific type of
		/// user keys (password, key file, ...). If at least one user
		/// key of that type is present, the function returns <c>true</c>.
		/// </summary>
		/// <param name="tUserKeyType">User key type.</param>
		/// <returns>Returns <c>true</c>, if the composite key contains
		/// a user key of the specified type.</returns>
		public boolean ContainsType(Class<?> tUserKeyType)
		{
			assert tUserKeyType != null;
			if(tUserKeyType == null) throw new IllegalArgumentException("tUserKeyType");

			for(IUserKey pKey : m_vUserKeys)
			{
				if(pKey.getClass().isAssignableFrom(tUserKeyType))
					return true;
			}

			return false;
		}

		/// <summary>
		/// Get the first user key of a specified type.
		/// </summary>
		/// <param name="tUserKeyType">Type of the user key to get.</param>
		/// <returns>Returns the first user key of the specified type
		/// or <c>null</c> if no key of that type is found.</returns>
		public IUserKey GetUserKey(Class<?> tUserKeyType)
		{
			assert tUserKeyType != null;
			if(tUserKeyType == null) throw new IllegalArgumentException("tUserKeyType");

			for(IUserKey pKey : m_vUserKeys)
			{
				if(pKey.getClass().isAssignableFrom(tUserKeyType))
					return pKey;
			}

			return null;
		}

		/// <summary>
		/// Creates the composite key from the supplied user key sources (password,
		/// key file, user account, computer ID, etc.).
		/// </summary>
		private byte[] CreateRawCompositeKey32()
		{
			ValidateUserKeys();

			// Concatenate user key data
			ByteArrayOutputStream ms = new ByteArrayOutputStream();
			for(IUserKey pKey : m_vUserKeys)
			{
				ProtectedBinary b = pKey.getKeyData();
				if(b != null)
				{
					byte[] pbKeyData = b.ReadData();
					ms.write(pbKeyData, 0, pbKeyData.length);
					MemUtil.ZeroByteArray(pbKeyData);
				}
			}

			return Digests.sha256(ms.toByteArray());
		}

		public boolean EqualsValue(CompositeKey ckOther)
		{
			if(ckOther == null) throw new IllegalArgumentException("ckOther");

			byte[] pbThis = CreateRawCompositeKey32();
			byte[] pbOther = ckOther.CreateRawCompositeKey32();
			boolean bResult = MemUtil.ArraysEqual(pbThis, pbOther);
			Arrays.fill(pbOther, (byte)0);
			Arrays.fill(pbThis, (byte)0);

			return bResult;
		}

		/// <summary>
		/// Generate a 32-bit wide key out of the composite key.
		/// </summary>
		/// <param name="pbKeySeed32">Seed used in the key transformation
		/// rounds. Must be a byte array containing exactly 32 bytes; must
		/// not be null.</param>
		/// <param name="uNumRounds">Number of key transformation rounds.</param>
		/// <returns>Returns a protected binary object that contains the
		/// resulting 32-bit wide key.</returns>
		public ProtectedBinary GenerateKey32(byte[] pbKeySeed32, long uNumRounds)
		{
			assert pbKeySeed32 != null;
			if(pbKeySeed32 == null) throw new IllegalArgumentException("pbKeySeed32");
			assert pbKeySeed32.length == 32;
			if(pbKeySeed32.length != 32) throw new IllegalArgumentException("pbKeySeed32");

			byte[] pbRaw32 = CreateRawCompositeKey32();
			if((pbRaw32 == null) || (pbRaw32.length != 32))
				{ assert false; return null; }

			byte[] pbTrf32 = TransformKey(pbRaw32, pbKeySeed32, uNumRounds);
			if((pbTrf32 == null) || (pbTrf32.length != 32))
				{ assert false; return null; }

			ProtectedBinary pbRet = new ProtectedBinary(true, pbTrf32);
			MemUtil.ZeroByteArray(pbTrf32);
			MemUtil.ZeroByteArray(pbRaw32);

			return pbRet;
		}

		private void ValidateUserKeys()
		{
			int nAccounts = 0;
		}

		/// <summary>
		/// Transform the current key <c>uNumRounds</c> times.
		/// </summary>
		/// <param name="pbOriginalKey32">The original key which will be transformed.
		/// This parameter won't be modified.</param>
		/// <param name="pbKeySeed32">Seed used for key transformations. Must not
		/// be <c>null</c>. This parameter won't be modified.</param>
		/// <param name="uNumRounds">Transformation count.</param>
		/// <returns>256-bit transformed key.</returns>
		private static byte[] TransformKey(byte[] pbOriginalKey32, byte[] pbKeySeed32,
			long uNumRounds)
		{
			if(pbOriginalKey32 == null) throw new IllegalArgumentException("pbOriginalKey32");
			if(pbOriginalKey32.length != 32) throw new IllegalArgumentException();

			assert (pbKeySeed32 != null && (pbKeySeed32.length == 32));
			if(pbKeySeed32 == null) throw new IllegalArgumentException("pbKeySeed32");
			if(pbKeySeed32.length != 32) throw new IllegalArgumentException();

			byte[] pbNewKey = new byte[32];
			System.arraycopy(pbOriginalKey32, 0, pbNewKey, 0, pbNewKey.length);

			// Try to use the native library first
//			if(NativeLib.TransformKey256(pbNewKey, pbKeySeed32, uNumRounds))
//				return (new SHA256Managed()).ComputeHash(pbNewKey);

			if(!TransformKeyManaged(pbNewKey, pbKeySeed32, uNumRounds))
				return null;

			return Digests.sha256(pbNewKey);
		}

		public static boolean TransformKeyManaged(byte[] pbNewKey32, byte[] pbKeySeed32,
			long uNumRounds)
		{
			byte[] pbIV = new byte[16];
			Arrays.fill(pbIV, (byte) 0);

            try {
                AESEngine engine = new AESEngine();
                engine.init(true, new KeyParameter(pbKeySeed32));
                if (engine.getBlockSize() != (128 / 8)) // AES block size
                {
                    assert false;
                    throw new RuntimeException();
                }

//                IvParameterSpec ivspec = new IvParameterSpec(pbIV);
//                SecretKeySpec key = new SecretKeySpec(pbKeySeed32, "AES");
//                c.init(Cipher.ENCRYPT_MODE, key, ivspec);

                for (long i = 0; i < uNumRounds; ++i) {
                    engine.processBlock(pbNewKey32, 0, pbNewKey32, 0);
                    engine.processBlock(pbNewKey32, 16, pbNewKey32, 16);
                }
//                engine.doFinal();
            } catch (Exception e) { throw new RuntimeException(e); }

			return true;
		}

		/// <summary>
		/// Benchmark the <c>TransformKey</c> method. Within
		/// <paramref name="uMilliseconds"/> ms, random keys will be transformed
		/// and the number of performed transformations are returned.
		/// </summary>
		/// <param name="uMilliseconds">Test duration in ms.</param>
		/// <param name="uStep">Stepping.
		/// <paramref name="uStep" /> should be a prime number. For fast processors
		/// (PCs) a value of <c>3001</c> is recommended, for slower processors (PocketPC)
		/// a value of <c>401</c> is recommended.</param>
		/// <returns>Number of transformations performed in the specified
		/// amount of time. Maximum value is <c>int.MaxValue</c>.</returns>
		public static long TransformKeyBenchmark(long uMilliseconds, long uStep)
		{
			long uRounds;

			// Try native method
//			if(NativeLib.TransformKeyBenchmark256(uMilliseconds, out uRounds))
//				return uRounds;

			byte[] pbKey = new byte[32];
			byte[] pbNewKey = new byte[32];
			for(int i = 0; i < pbKey.length; ++i)
			{
				pbKey[i] = (byte)i;
				pbNewKey[i] = (byte)i;
			}

			byte[] pbIV = new byte[16];
			Arrays.fill(pbIV, (byte) 0);
            try {
                AESEngine engine = new AESEngine();
                engine.init(true, new KeyParameter(pbKey));

                if (engine.getBlockSize() != (128 / 8)) // AES block size
                {
                    throw new RuntimeException();
                }

                uRounds = 0;
                long tStart = System.currentTimeMillis();
                while (true) {
                    for (long j = 0; j < uStep; ++j) {
                        engine.processBlock(pbNewKey, 0, pbNewKey, 0);
                        engine.processBlock(pbNewKey, 16, pbNewKey, 16);
                    }

                    uRounds += uStep;
                    if (uRounds < uStep) // Overflow check
                    {
                        uRounds = Long.MAX_VALUE;
                        break;
                    }

                    long tElapsed = System.currentTimeMillis() - tStart;
                    if (tElapsed > uMilliseconds) break;
                }

                return uRounds;
            } catch (Exception e) { throw new RuntimeException(e); }
		}
	}

