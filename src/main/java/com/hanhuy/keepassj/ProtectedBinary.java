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

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

//[Flags]
	enum PbCryptFlags
	{
		None,
		Encrypt,
		Decrypt
	}
    enum PbMemProt
    {
        None,
        ProtectedMemory,
        Salsa20,
        ExtCrypt
    }

	interface PbCryptDelegate {
        public void delegate(byte[] pbData, PbCryptFlags cf,
                             long lID);
    }

	/// <summary>
	/// Represents a protected binary, i.e. a byte array that is encrypted
	/// in memory. A <c>ProtectedBinary</c> Object is immutable and
	/// thread-safe.
	/// </summary>
	public class ProtectedBinary
	{
		private final static int BlockSize = 16;

		private static PbCryptDelegate g_fExtCrypt = null;
		/// <summary>
		/// A plugin can provide a custom memory protection method
		/// by assigning a non-null delegate to this property.
		/// </summary>
		public static PbCryptDelegate getExtCrypt()
		{
			return g_fExtCrypt;
		}
        public void setExtCrypt(PbCryptDelegate value) { g_fExtCrypt = value; }

		// Local copy of the delegate that was used for encryption,
		// in order to allow correct decryption even when the global
		// delegate changes
		private PbCryptDelegate m_fExtCrypt = null;


		// ProtectedMemory is supported only on Windows 2000 SP3 and higher
		private static boolean g_bProtectedMemorySupported = false;
		private static boolean ProtectedMemorySupported = false;

		private static AtomicLong g_lCurID = new AtomicLong(0);
		private long m_lID;

		private byte[] m_pbData; // Never null

		// The real length of the data; this value can be different from
		// m_pbData.Length, as the length of m_pbData always is a multiple
		// of BlockSize (required for ProtectedMemory)
		private int m_uDataLen;

		private boolean m_bProtected; // Protection requested by the caller

		private PbMemProt m_mp = PbMemProt.None; // Actual protection

		private final Object m_objSync = new Object();

		private static AtomicReference<byte[]> g_pbKey32 = new AtomicReference<byte[]>();

		/// <summary>
		/// A flag specifying whether the <c>ProtectedBinary</c> Object has
		/// turned on memory protection or not.
		/// </summary>
		public boolean isProtected()
		{
			return m_bProtected;
		}

		/// <summary>
		/// Length of the stored data.
		/// </summary>
		public int getLength()
		{
			return m_uDataLen;
		}

		/// <summary>
		/// Construct a new, empty protected binary data Object.
		/// Protection is disabled.
		/// </summary>
		public ProtectedBinary()
		{
			Init(false, new byte[0]);
		}

		/// <summary>
		/// Construct a new protected binary data Object.
		/// </summary>
		/// <param name="bEnableProtection">If this paremeter is <c>true</c>,
		/// the data will be encrypted in memory. If it is <c>false</c>, the
		/// data is stored in plain-text in the process memory.</param>
		/// <param name="pbData">Value of the protected Object.
		/// The input parameter is not modified and
		/// <c>ProtectedBinary</c> doesn't take ownership of the data,
		/// i.e. the caller is responsible for clearing it.</param>
		public ProtectedBinary(boolean bEnableProtection, byte[] pbData)
		{
			Init(bEnableProtection, pbData);
		}

		/// <summary>
		/// Construct a new protected binary data Object. Copy the data from
		/// a <c>XorredBuffer</c> Object.
		/// </summary>
		/// <param name="bEnableProtection">Enable protection or not.</param>
		/// <param name="xbProtected"><c>XorredBuffer</c> Object used to
		/// initialize the <c>ProtectedBinary</c> Object.</param>
		public ProtectedBinary(boolean bEnableProtection, XorredBuffer xbProtected)
		{
			assert xbProtected != null;
			if(xbProtected == null) throw new IllegalArgumentException("xbProtected");

			byte[] pb = xbProtected.ReadPlainText();
			Init(bEnableProtection, pb);
			MemUtil.ZeroByteArray(pb);
		}

		private void Init(boolean bEnableProtection, byte[] pbData)
		{
			if(pbData == null) throw new IllegalArgumentException("pbData");

			m_lID = g_lCurID.incrementAndGet();

			m_bProtected = bEnableProtection;
			m_uDataLen = pbData.length;

			final int bs = ProtectedBinary.BlockSize;
			int nBlocks = (int)m_uDataLen / bs;
			if((nBlocks * bs) < (int)m_uDataLen) ++nBlocks;
			assert (nBlocks * bs >= (int)m_uDataLen);

			m_pbData = new byte[nBlocks * bs];
            System.arraycopy(pbData, 0, m_pbData, 0, m_uDataLen);

			Encrypt();
		}

		private void Encrypt()
		{
			assert m_mp == PbMemProt.None;

			// Nothing to do if caller didn't request protection
			if(!m_bProtected) return;

			// ProtectedMemory.Protect throws for data size == 0
			if(m_pbData.length == 0) return;

			PbCryptDelegate f = g_fExtCrypt;
			if(f != null)
			{
				f.delegate(m_pbData, PbCryptFlags.Encrypt, m_lID);

				m_fExtCrypt = f;
				m_mp = PbMemProt.ExtCrypt;
				return;
			}

			if(ProtectedBinary.ProtectedMemorySupported)
			{
                // NOT SUPPORTED!
				//ProtectedMemory.Protect(m_pbData, MemoryProtectionScope.SameProcess);

				m_mp = PbMemProt.ProtectedMemory;
				return;
			}

			byte[] pbKey32 = g_pbKey32.get();
			if(pbKey32 == null)
			{
                pbKey32 = CryptoRandom.getInstance().GetRandomBytes(32);

                byte[] pbUpd = g_pbKey32.getAndSet(pbKey32);
				if(pbUpd != null) pbKey32 = pbUpd;
			}

			Salsa20Cipher s = new Salsa20Cipher(pbKey32, MemUtil.UInt64ToBytes(m_lID));
			s.Encrypt(m_pbData, m_pbData.length, true);
			s.Dispose();
			m_mp = PbMemProt.Salsa20;
		}

		private void Decrypt()
		{
			if(m_pbData.length == 0) return;

			if(m_mp == PbMemProt.ProtectedMemory) // no protected memory
				;//ProtectedMemory.Unprotect(m_pbData, MemoryProtectionScope.SameProcess);
			else if(m_mp == PbMemProt.Salsa20)
			{
				Salsa20Cipher s = new Salsa20Cipher(g_pbKey32.get(),
					MemUtil.UInt64ToBytes(m_lID));
				s.Encrypt(m_pbData, m_pbData.length, true);
				s.Dispose();
			}
			else if(m_mp == PbMemProt.ExtCrypt)
				m_fExtCrypt.delegate(m_pbData, PbCryptFlags.Decrypt, m_lID);
			else { assert m_mp == PbMemProt.None; }

			m_mp = PbMemProt.None;
		}

		/// <summary>
		/// Get a copy of the protected data as a byte array.
		/// Please note that the returned byte array is not protected and
		/// can therefore been read by any other application.
		/// Make sure that your clear it properly after usage.
		/// </summary>
		/// <returns>Unprotected byte array. This is always a copy of the internal
		/// protected data and can therefore be cleared safely.</returns>
		public byte[] ReadData()
		{
			if(m_uDataLen == 0) return new byte[0];

			byte[] pbReturn = new byte[m_uDataLen];

			synchronized(m_objSync)
			{
				Decrypt();
				System.arraycopy(m_pbData, 0, pbReturn, 0, m_uDataLen);
				Encrypt();
			}

			return pbReturn;
		}

		/// <summary>
		/// Read the protected data and return it protected with a sequence
		/// of bytes generated by a random stream.
		/// </summary>
		/// <param name="crsRandomSource">Random number source.</param>
		public byte[] ReadXorredData(CryptoRandomStream crsRandomSource)
		{
			assert crsRandomSource != null;
			if(crsRandomSource == null) throw new IllegalArgumentException("crsRandomSource");

			byte[] pbData = ReadData();
			int uLen = (int)pbData.length;

			byte[] randomPad = crsRandomSource.GetRandomBytes(uLen);
			assert randomPad.length == pbData.length;

			for(int i = 0; i < uLen; ++i)
				pbData[i] ^= randomPad[i];

			return pbData;
		}

		private Integer m_hash = null;
        @Override
		public int hashCode()
		{
			if(m_hash != null) return m_hash;

			int h = (m_bProtected ? 0x7B11D289 : 0);

			byte[] pb = ReadData();
            for (byte aPb : pb) h = (h << 3) + h + aPb;
			MemUtil.ZeroByteArray(pb);

			m_hash = h;
			return h;
		}

        @Override
		public boolean equals(Object obj)
		{
			return obj instanceof ProtectedBinary && Equals((ProtectedBinary) obj);
		}

		public boolean Equals(ProtectedBinary other)
		{
			if(other == null) return false; // No assert

			if(m_bProtected != other.m_bProtected) return false;
			if(m_uDataLen != other.m_uDataLen) return false;

			byte[] pbL = ReadData();
			byte[] pbR = other.ReadData();
			boolean bEq = MemUtil.ArraysEqual(pbL, pbR);
			MemUtil.ZeroByteArray(pbL);
			MemUtil.ZeroByteArray(pbR);

			return bEq;
		}
	}
