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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

/// <summary>
	/// Represents an in-memory encrypted String.
	/// <c>ProtectedString</c> objects are immutable and thread-safe.
	/// </summary>
	public class ProtectedString
	{
		// Exactly one of the following will be non-null
		private ProtectedBinary m_pbUtf8 = null;
		private String m_strPlainText = null;

		private boolean m_bIsProtected;

		public static ProtectedString Empty = new ProtectedString();

		/// <summary>
		/// A flag specifying whether the <c>ProtectedString</c> object
		/// has turned on memory protection or not.
		/// </summary>
		public boolean isProtected()
		{
			return m_bIsProtected;
		}

		public boolean isEmpty()
		{
				ProtectedBinary pBin = m_pbUtf8; // Local ref for thread-safety
				if(pBin != null) return (pBin.getLength() == 0);

				assert m_strPlainText != null;
				return (m_strPlainText.length() == 0);
		}

		private int m_nCachedLength = -1;
		public int Length()
		{
				if(m_nCachedLength >= 0) return m_nCachedLength;

				ProtectedBinary pBin = m_pbUtf8; // Local ref for thread-safety
				if(pBin != null)
				{
					byte[] pbPlain = pBin.ReadData();
                    // pfn: unfortunate circumstance of the port, ability to zero out memory is lost
                    CharBuffer decoded = StrUtil.Utf8.decode(ByteBuffer.wrap(pbPlain));
					m_nCachedLength = decoded.length();
                    Arrays.fill(decoded.array(), (char) 0);
					MemUtil.ZeroByteArray(pbPlain);
				}
				else
				{
					assert m_strPlainText != null;
					m_nCachedLength = m_strPlainText.length();
				}

				return m_nCachedLength;
		}

		/// <summary>
		/// Construct a new protected String object. Protection is
		/// disabled.
		/// </summary>
		public ProtectedString()
		{
			Init(false, "");
		}

		/// <summary>
		/// Construct a new protected String. The String is initialized
		/// to the value supplied in the parameters.
		/// </summary>
		/// <param name="bEnableProtection">If this parameter is <c>true</c>,
		/// the String will be protected in memory (encrypted). If it
		/// is <c>false</c>, the String will be stored as plain-text.</param>
		/// <param name="strValue">The initial String value.</param>
		public ProtectedString(boolean bEnableProtection, String strValue)
		{
			Init(bEnableProtection, strValue);
		}

		/// <summary>
		/// Construct a new protected String. The String is initialized
		/// to the value supplied in the parameters (UTF-8 encoded String).
		/// </summary>
		/// <param name="bEnableProtection">If this parameter is <c>true</c>,
		/// the String will be protected in memory (encrypted). If it
		/// is <c>false</c>, the String will be stored as plain-text.</param>
		/// <param name="vUtf8Value">The initial String value, encoded as
		/// UTF-8 byte array. This parameter won't be modified; the caller
		/// is responsible for clearing it.</param>
		public ProtectedString(boolean bEnableProtection, byte[] vUtf8Value)
		{
			Init(bEnableProtection, vUtf8Value);
		}

		/// <summary>
		/// Construct a new protected String. The String is initialized
		/// to the value passed in the <c>XorredBuffer</c> object.
		/// </summary>
		/// <param name="bEnableProtection">Enable protection or not.</param>
		/// <param name="xbProtected"><c>XorredBuffer</c> object containing the
		/// String in UTF-8 representation. The UTF-8 String must not
		/// be <c>null</c>-terminated.</param>
		public ProtectedString(boolean bEnableProtection, XorredBuffer xbProtected)
		{
			assert xbProtected != null;
			if(xbProtected == null) throw new IllegalArgumentException("xbProtected");

			byte[] pb = xbProtected.ReadPlainText();
			Init(bEnableProtection, pb);
			MemUtil.ZeroByteArray(pb);
		}

		private void Init(boolean bEnableProtection, String str)
		{
			if(str == null) throw new IllegalArgumentException("str");

			m_bIsProtected = bEnableProtection;

			// The String already is in memory and immutable,
			// protection would be useless
			m_strPlainText = str;
		}

		private void Init(boolean bEnableProtection, byte[] pbUtf8)
		{
			if(pbUtf8 == null) throw new IllegalArgumentException("pbUtf8");

			m_bIsProtected = bEnableProtection;

			if(bEnableProtection)
				m_pbUtf8 = new ProtectedBinary(true, pbUtf8);
			else
				m_strPlainText = new String(pbUtf8, 0, pbUtf8.length, StrUtil.Utf8);
		}

		/// <summary>
		/// Convert the protected String to a normal String object.
		/// Be careful with this function, the returned String object
		/// isn't protected anymore and stored in plain-text in the
		/// process memory.
		/// </summary>
		/// <returns>Plain-text String. Is never <c>null</c>.</returns>
		public String ReadString()
		{
			if(m_strPlainText != null) return m_strPlainText;

			byte[] pb = ReadUtf8();
			String str = pb.length == 0 ? "" :
				StrUtil.Utf8.decode(ByteBuffer.wrap(pb)).toString();
			// No need to clear pb

			// As the text is now visible in process memory anyway,
			// there's no need to protect it anymore
			m_strPlainText = str;
			m_pbUtf8 = null; // Thread-safe order

			return str;
		}

		/// <summary>
		/// Read out the String and return a byte array that contains the
		/// String encoded using UTF-8. The returned String is not protected
		/// anymore!
		/// </summary>
		/// <returns>Plain-text UTF-8 byte array.</returns>
		public byte[] ReadUtf8()
		{
			ProtectedBinary pBin = m_pbUtf8; // Local ref for thread-safety
			if(pBin != null) return pBin.ReadData();

			return StrUtil.Utf8.encode(m_strPlainText).array();
		}

		/// <summary>
		/// Read the protected String and return it protected with a sequence
		/// of bytes generated by a random stream.
		/// </summary>
		/// <param name="crsRandomSource">Random number source.</param>
		/// <returns>Protected String.</returns>
		public byte[] ReadXorredString(CryptoRandomStream crsRandomSource)
		{
			assert crsRandomSource != null; if(crsRandomSource == null) throw new IllegalArgumentException("crsRandomSource");

			byte[] pbData = ReadUtf8();
			int uLen = pbData.length;

            byte[] randomPad = crsRandomSource.GetRandomBytes(uLen);
			assert randomPad.length == pbData.length;

			for(int i = 0; i < uLen; ++i)
				pbData[i] ^= randomPad[i];

			return pbData;
		}

		public ProtectedString WithProtection(boolean bProtect)
		{
			if(bProtect == m_bIsProtected) return this;

			byte[] pb = ReadUtf8();
			ProtectedString ps = new ProtectedString(bProtect, pb);
			MemUtil.ZeroByteArray(pb);
			return ps;
		}

		public ProtectedString Insert(int iStart, String strInsert)
		{
			if(iStart < 0) throw new ArrayIndexOutOfBoundsException("iStart");
			if(strInsert == null) throw new IllegalArgumentException("strInsert");
			if(strInsert.length() == 0) return this;

			// Only operate directly with strings when m_bIsProtected is
			// false, not in the case of non-null m_strPlainText, because
			// the operation creates a new sequence in memory
			if(!m_bIsProtected)
				return new ProtectedString(false, StrUtil.Insert(ReadString(),
					iStart, strInsert));

			Charset utf8 = StrUtil.Utf8;

			byte[] pb = ReadUtf8();
			char[] v = utf8.decode(ByteBuffer.wrap(pb)).array();
			char[] vNew;

			try
			{
				if(iStart > v.length)
					throw new ArrayIndexOutOfBoundsException("iStart");

				char[] vIns = strInsert.toCharArray();

				vNew = new char[v.length + vIns.length];
				System.arraycopy(v, 0, vNew, 0, iStart);
				System.arraycopy(vIns, 0, vNew, iStart, vIns.length);
				System.arraycopy(v, iStart, vNew, iStart + vIns.length,
					v.length - iStart);
			}
			finally
			{
				Arrays.fill(v, (char)0);
				MemUtil.ZeroByteArray(pb);
			}

			byte[] pbNew = utf8.encode(CharBuffer.wrap(vNew)).array();
			ProtectedString ps = new ProtectedString(m_bIsProtected, pbNew);

//			assert utf8.GetString(pbNew, 0, pbNew.Length) ==
//				ReadString().Insert(iStart, strInsert);

			Arrays.fill(vNew, (char)0);
			MemUtil.ZeroByteArray(pbNew);
			return ps;
		}

		public ProtectedString Remove(int iStart, int nCount)
		{
			if(iStart < 0) throw new ArrayIndexOutOfBoundsException("iStart");
			if(nCount < 0) throw new ArrayIndexOutOfBoundsException("nCount");
			if(nCount == 0) return this;

			// Only operate directly with strings when m_bIsProtected is
			// false, not in the case of non-null m_strPlainText, because
			// the operation creates a new sequence in memory
			if(!m_bIsProtected)
				return new ProtectedString(false, StrUtil.Remove(ReadString(),
                        iStart, nCount));

			Charset utf8 = StrUtil.Utf8;

			byte[] pb = ReadUtf8();
			char[] v = utf8.decode(ByteBuffer.wrap(pb)).array();
			char[] vNew;

			try
			{
				if((iStart + nCount) > v.length)
					throw new IllegalArgumentException("iStart + nCount");

				vNew = new char[v.length - nCount];
				System.arraycopy(v, 0, vNew, 0, iStart);
				System.arraycopy(v, iStart + nCount, vNew, iStart, v.length -
					(iStart + nCount));
			}
			finally
			{
				Arrays.fill(v, (char)0);
				MemUtil.ZeroByteArray(pb);
			}

			byte[] pbNew = utf8.encode(CharBuffer.wrap(vNew)).array();
			ProtectedString ps = new ProtectedString(m_bIsProtected, pbNew);

//			assert utf8.GetString(pbNew, 0, pbNew.Length) ==
//				ReadString().Remove(iStart, nCount);

			Arrays.fill(vNew, (char)0);
			MemUtil.ZeroByteArray(pbNew);
			return ps;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			ProtectedString that = (ProtectedString) o;

			return m_bIsProtected == that.m_bIsProtected &&
					ReadString().equals(that.ReadString());

		}

		@Override
		public int hashCode() {
			return ReadString().hashCode();
		}
	}
