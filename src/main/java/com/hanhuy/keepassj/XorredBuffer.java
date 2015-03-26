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
	/// Represents an object that is encrypted using a XOR pad until
	/// it is read. <c>XorredBuffer</c> objects are immutable and
	/// thread-safe.
	/// </summary>
	public class XorredBuffer
	{
		private byte[] m_pbData; // Never null
		private byte[] m_pbXorPad; // Always valid for m_pbData

		/// <summary>
		/// Length of the protected data in bytes.
		/// </summary>
		public int getLength()
		{
			return (int)m_pbData.length;
		}

		/// <summary>
		/// Construct a new XOR-protected object using a protected byte array
		/// and a XOR pad that decrypts the protected data. The
		/// <paramref name="pbProtectedData" /> byte array must have the same size
		/// as the <paramref name="pbXorPad" /> byte array.
		/// The <c>XorredBuffer</c> object takes ownership of the two byte
		/// arrays, i.e. the caller must not use or modify them afterwards.
		/// </summary>
		/// <param name="pbProtectedData">Protected data (XOR pad applied).</param>
		/// <param name="pbXorPad">XOR pad that can be used to decrypt the
		/// <paramref name="pbProtectedData" /> parameter.</param>
		/// <exception cref="System.IllegalArgumentException">Thrown if one of the input
		/// parameters is <c>null</c>.</exception>
		/// <exception cref="System.ArgumentException">Thrown if the byte arrays are
		/// of different size.</exception>
		public XorredBuffer(byte[] pbProtectedData, byte[] pbXorPad)
		{
			if(pbProtectedData == null) { assert false; throw new IllegalArgumentException("pbProtectedData"); }
			if(pbXorPad == null) { assert false; throw new IllegalArgumentException("pbXorPad"); }

			assert pbProtectedData.length == pbXorPad.length;
			if(pbProtectedData.length != pbXorPad.length) throw new IllegalArgumentException();

			m_pbData = pbProtectedData;
			m_pbXorPad = pbXorPad;
		}

		/// <summary>
		/// Get a copy of the plain-text. The caller is responsible
		/// for clearing the byte array safely after using it.
		/// </summary>
		/// <returns>Unprotected plain-text byte array.</returns>
		public byte[] ReadPlainText()
		{
			byte[] pbPlain = new byte[m_pbData.length];

			for(int i = 0; i < pbPlain.length; ++i)
				pbPlain[i] = (byte)(m_pbData[i] ^ m_pbXorPad[i]);

			return pbPlain;
		}

		/* public bool EqualsValue(XorredBuffer xb)
		{
			if(xb == null) { assert false; throw new IllegalArgumentException("xb"); }

			if(xb.m_pbData.Length != m_pbData.Length) return false;

			for(int i = 0; i < m_pbData.Length; ++i)
			{
				byte bt1 = (byte)(m_pbData[i] ^ m_pbXorPad[i]);
				byte bt2 = (byte)(xb.m_pbData[i] ^ xb.m_pbXorPad[i]);

				if(bt1 != bt2) return false;
			}

			return true;
		}

		public bool EqualsValue(byte[] pb)
		{
			if(pb == null) { assert false; throw new IllegalArgumentException("pb"); }

			if(pb.Length != m_pbData.Length) return false;

			for(int i = 0; i < m_pbData.Length; ++i)
			{
				if((byte)(m_pbData[i] ^ m_pbXorPad[i]) != pb[i]) return false;
			}

			return true;
		} */
	}
