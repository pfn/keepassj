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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Date;
import java.util.UUID;

/// <summary>
	/// Cryptographically strong random number generator. The returned values
	/// are unpredictable and cannot be reproduced.
	/// <c>CryptoRandom</c> is a singleton class.
	/// </summary>
	public class CryptoRandom
	{
		private byte[] m_pbEntropyPool = new byte[64];
		private int m_uCounter;
		private SecureRandom m_rng = new SecureRandom();
		private long m_uGeneratedBytesCount = 0;

		private final Object m_oSyncRoot = new Object();

		private static CryptoRandom m_pInstance = null;
		public static CryptoRandom getInstance()
		{
				if(m_pInstance != null) return m_pInstance;

				m_pInstance = new CryptoRandom();
				return m_pInstance;
		}

		/// <summary>
		/// Get the number of random bytes that this instance generated so far.
		/// Note that this number can be higher than the number of random bytes
		/// actually requested using the <c>GetRandomBytes</c> method.
		/// </summary>
		public long getGeneratedBytesCount()
		{
				long u;
				synchronized(m_oSyncRoot) { u = m_uGeneratedBytesCount; }
				return u;
		}

		/// <summary>
		/// Event that is triggered whenever the internal <c>GenerateRandom256</c>
		/// method is called to generate random bytes.
		/// </summary>
		public EventHandler GenerateRandom256Pre;

		private CryptoRandom()
		{
			SecureRandom r = new SecureRandom();
			m_uCounter = r.nextInt();

			AddEntropy(GetSystemData(r));
			AddEntropy(GetCspData());
		}

		/// <summary>
		/// Update the internal seed of the random number generator based
		/// on entropy data.
		/// This method is thread-safe.
		/// </summary>
		/// <param name="pbEntropy">Entropy bytes.</param>
		public void AddEntropy(byte[] pbEntropy)
		{
			if(pbEntropy == null) { assert false; return; }
			if(pbEntropy.length == 0) { assert false; return; }

			byte[] pbNewData = pbEntropy;
			if(pbEntropy.length >= 64)
			{
                // or get SHA-512
                try {
                    MessageDigest shaNew = MessageDigest.getInstance("SHA-256");
                    pbNewData = shaNew.digest(pbEntropy);
                } catch (Exception e) { throw new RuntimeException(e); }
			}

			ByteArrayOutputStream ms = new ByteArrayOutputStream();
			synchronized(m_oSyncRoot)
			{
				ms.write(m_pbEntropyPool, 0, m_pbEntropyPool.length);
				ms.write(pbNewData, 0, pbNewData.length);

				byte[] pbFinal = ms.toByteArray();
                try {
                    // TODO try to fetch SHA-512 as well
                    MessageDigest shaPool = MessageDigest.getInstance("SHA-256");
                    m_pbEntropyPool = shaPool.digest(pbFinal);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
			}
		}

		private static byte[] GetSystemData(SecureRandom rWeak)
		{
			ByteArrayOutputStream ms = new ByteArrayOutputStream();
			byte[] pb;

			pb = MemUtil.UInt32ToBytes((int)System.currentTimeMillis());
			ms.write(pb, 0, pb.length);

			pb = TimeUtil.PackTime(new Date());
			ms.write(pb, 0, pb.length);

			pb = MemUtil.UInt32ToBytes((int)rWeak.nextInt());
			ms.write(pb, 0, pb.length);

			try
			{
				pb = MemUtil.UInt32ToBytes((int)Runtime.getRuntime().availableProcessors());
				ms.write(pb, 0, pb.length);
				pb = MemUtil.UInt64ToBytes((long)Runtime.getRuntime().totalMemory());
				ms.write(pb, 0, pb.length);

				String v = System.getProperty("os.version");
				pb = MemUtil.UInt32ToBytes((int)v.hashCode());
				ms.write(pb, 0, pb.length);

				// Not supported in Mono 1.2.6:
				// pb = MemUtil.UInt32ToBytes((int)p.SessionId);
				// ms.Write(pb, 0, pb.Length);
			}
			catch(Exception e) { }
            UUID uuid = UUID.randomUUID();
            pb = new byte[16];
            ByteBuffer buffer = ByteBuffer.wrap(pb);
            buffer.putLong(uuid.getMostSignificantBits());
            buffer.putLong(uuid.getLeastSignificantBits());
			ms.write(pb, 0, pb.length);

			byte[] pbAll = ms.toByteArray();
			return pbAll;
		}

		private byte[] GetCspData()
		{
			byte[] pbCspRandom = new byte[32];
			m_rng.nextBytes(pbCspRandom);
			return pbCspRandom;
		}

		private byte[] GenerateRandom256()
		{
			if(this.GenerateRandom256Pre != null)
				this.GenerateRandom256Pre.delegate(this, null);

			byte[] pbFinal;
			synchronized (m_oSyncRoot)
			{
				m_uCounter += 386047; // Prime number
				byte[] pbCounter = MemUtil.UInt32ToBytes(m_uCounter);

				byte[] pbCspRandom = GetCspData();

				ByteArrayOutputStream ms = new ByteArrayOutputStream();
				ms.write(m_pbEntropyPool, 0, m_pbEntropyPool.length);
				ms.write(pbCounter, 0, pbCounter.length);
				ms.write(pbCspRandom, 0, pbCspRandom.length);
				pbFinal = ms.toByteArray();
				assert pbFinal.length == (m_pbEntropyPool.length +
					pbCounter.length + pbCspRandom.length);
                try {
                    ms.close();
                } catch (IOException e) { }

				m_uGeneratedBytesCount += 32;
			}

            try {
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                return sha256.digest(pbFinal);
            } catch (Exception e) { throw new IllegalStateException(e); }
		}

		/// <summary>
		/// Get a number of cryptographically strong random bytes.
		/// This method is thread-safe.
		/// </summary>
		/// <param name="uRequestedBytes">Number of requested random bytes.</param>
		/// <returns>A byte array consisting of <paramref name="uRequestedBytes" />
		/// random bytes.</returns>
		public byte[] GetRandomBytes(int uRequestedBytes)
		{
			if(uRequestedBytes == 0) return new byte[0]; // Allow zero-length array

			byte[] pbRes = new byte[uRequestedBytes];
			long lPos = 0;

			while(uRequestedBytes != 0)
			{
				byte[] pbRandom256 = GenerateRandom256();
				assert pbRandom256.length == 32;

				long lCopy = (long)((uRequestedBytes < 32) ? uRequestedBytes : 32);

				System.arraycopy(pbRandom256, 0, pbRes, (int)lPos, (int)lCopy);

				lPos += lCopy;
				uRequestedBytes -= (int)lCopy;
			}

			assert (int)lPos == pbRes.length;
			return pbRes;
		}
	}
