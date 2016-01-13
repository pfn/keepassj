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

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.io.BaseEncoding;

import java.io.*;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/// <summary>
	/// Contains static buffer manipulation and String conversion routines.
	/// </summary>
	public class MemUtil
	{
		private static final int[] m_vSBox = new int[] {
			0xCD2FACB3, 0xE78A7F5C, 0x6F0803FC, 0xBCF6E230,
			0x3A321712, 0x06403DB1, 0xD2F84B95, 0xDF22A6E4,
			0x07CE9E5B, 0x31788A0C, 0xF683F6F4, 0xEA061F49,
			0xFA5C2ACA, 0x4B9E494E, 0xB0AB25BA, 0x767731FC,
			0x261893A7, 0x2B09F2CE, 0x046261E4, 0x41367B4B,
			0x18A7F225, 0x8F923C0E, 0x5EF3A325, 0x28D0435E,
			0x84C22919, 0xED66873C, 0x8CEDE444, 0x7FC47C24,
			0xFCFC6BA3, 0x676F928D, 0xB4147187, 0xD8FB126E,
			0x7D798D17, 0xFF82E424, 0x1712FA5B, 0xABB09DD5,
			0x8156BA63, 0x84E4D969, 0xC937FB9A, 0x2F1E5BFC,
			0x178ECA11, 0x0E71CD5F, 0x52AAC6F4, 0x71EEFC8F,
			0x7090D749, 0x21CACA31, 0x92996378, 0x0939A8A8,
			0xE9EE1934, 0xD2718616, 0xF2500543, 0xB911873C,
			0xD3CB3EEC, 0x2BA0DBEB, 0xB42D0A27, 0xECE67C0F,
			0x302925F0, 0x6114F839, 0xD39E6307, 0xE28970D6,
			0xEB982F99, 0x941B4CDF, 0xC540E550, 0x8124FC45,
			0x98B025C7, 0xE2BF90EA, 0x4F57C976, 0xCF546FE4,
			0x59566DC8, 0xE3F4360D, 0xF5F9D231, 0xD6180B22,
			0xB54E088A, 0xB5DFE6A6, 0x3637A36F, 0x056E9284,
			0xAFF8FBC5, 0x19E01648, 0x8611F043, 0xDAE44337,
			0xF61B6A1C, 0x257ACD9E, 0xDD35F507, 0xEF05CAFA,
			0x05EB4A83, 0xFC25CA92, 0x0A4728E6, 0x9CF150EF,
			0xAEEF67DE, 0xA9472337, 0x57C81EFE, 0x3E5E009F,
			0x02CB03BB, 0x2BA85674, 0xF21DC251, 0x78C34A34,
			0xABB1F5BF, 0xB95A2FBD, 0x1FB47777, 0x9A96E8AC,
			0x5D2D2838, 0x55AAC92A, 0x99EE324E, 0x10F6214B,
			0x58ABDFB1, 0x2008794D, 0xBEC880F0, 0xE75E5341,
			0x88015C34, 0x352D8FBF, 0x622B7F6C, 0xF5C59EA2,
			0x1F759D8E, 0xADE56159, 0xCC7B4C25, 0x5B8BC48C,
			0xB6BD15AF, 0x3C5B5110, 0xE74A7C3D, 0xEE613161,
			0x156A1C67, 0x72C06817, 0xEA0A6F69, 0x4CECF993,
			0xCA9D554C, 0x8E20361F, 0x42D396B9, 0x595DE578,
			0x749D7955, 0xFD1BA5FD, 0x81FC160E, 0xDB97E28C,
			0x7CF148F7, 0x0B0B3CF5, 0x534DE605, 0x46421066,
			0xD4B68DD1, 0x9E479CE6, 0xAE667A9D, 0xBC082082,
			0xB06DD6EF, 0x20F0F23F, 0xB99E1551, 0xF47A2E3A,
			0x71DA50C6, 0x67B65779, 0x2A8CB376, 0x1EA71EEE,
			0x29ABCD50, 0xB6EB0C6B, 0x23C10511, 0x6F3F2144,
			0x6AF23012, 0xF696BD9E, 0xB94099D8, 0xAD5A9C81,
			0x7A0794FA, 0x7EDF59D6, 0x1E72E574, 0x8561913C,
			0x4E4D568F, 0xEECB9928, 0x9C124D2E, 0x0848B82C,
			0xF1CA395F, 0x9DAF43DC, 0xF77EC323, 0x394E9B59,
			0x7E200946, 0x8B811D68, 0x16DA3305, 0xAB8DE2C3,
			0xE6C53B64, 0x98C2D321, 0x88A97D81, 0xA7106419,
			0x8E52F7BF, 0x8ED262AF, 0x7CCA974E, 0xF0933241,
			0x040DD437, 0xE143B3D4, 0x3019F56F, 0xB741521D,
			0xF1745362, 0x4C435F9F, 0xB4214D0D, 0x0B0C348B,
			0x5051D189, 0x4C30447E, 0x7393D722, 0x95CEDD0B,
			0xDD994E80, 0xC3D22ED9, 0x739CD900, 0x131EB9C4,
			0xEF1062B2, 0x4F0DE436, 0x52920073, 0x9A7F3D80,
			0x896E7B1B, 0x2C8BBE5A, 0xBD304F8A, 0xA993E22C,
			0x134C41A0, 0xFA989E00, 0x39CE9726, 0xFB89FCCF,
			0xE8FBAC97, 0xD4063FFC, 0x935A2B5A, 0x44C8EE83,
			0xCB2BC7B6, 0x02989E92, 0x75478BEA, 0x144378D0,
			0xD853C087, 0x8897A34E, 0xDD23629D, 0xBDE2A2A2,
			0x581D8ECC, 0x5DA8AEE8, 0xFF8AAFD0, 0xBA2BCF6E,
			0x4BD98DAC, 0xF2EDB9E4, 0xFA2DC868, 0x47E84661,
			0xECEB1C7D, 0x41705CA4, 0x5982E4D4, 0xEB5204A1,
			0xD196CAFB, 0x6414804D, 0x3ABD4B46, 0x8B494C26,
			0xB432D52B, 0x39C5356B, 0x6EC80BF7, 0x71BE5483,
			0xCEC4A509, 0xE9411D61, 0x52F341E5, 0xD2E6197B,
			0x4F02826C, 0xA9E48838, 0xD1F8F247, 0xE4957FB3,
			0x586CCA99, 0x9A8B6A5B, 0x4998FBEA, 0xF762BE4C,
			0x90DFE33C, 0x9731511E, 0x88C6A82F, 0xDD65A4D4
		};

		/// <summary>
		/// Convert a hexadecimal String to a byte array. The input String must be
		/// even (i.e. its length is a multiple of 2).
		/// </summary>
		/// <param name="strHex">String containing hexadecimal characters.</param>
		/// <returns>Returns a byte array. Returns <c>null</c> if the String parameter
		/// was <c>null</c> or is an uneven String (i.e. if its length isn't a
		/// multiple of 2).</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if <paramref name="strHex" />
		/// is <c>null</c>.</exception>
		public static byte[] HexStringToByteArray(String strHex)
		{
			if(strHex == null) { assert false; throw new IllegalArgumentException("strHex"); }
            return BaseEncoding.base16().decode(strHex);
		}

		/// <summary>
		/// Convert a byte array to a hexadecimal String.
		/// </summary>
		/// <param name="pbArray">Input byte array.</param>
		/// <returns>Returns the hexadecimal String representing the byte
		/// array. Returns <c>null</c>, if the input byte array was <c>null</c>. Returns
		/// an empty String, if the input byte array has length 0.</returns>
		public static String ByteArrayToHexString(byte[] pbArray)
		{
			if(pbArray == null) return null;
            return BaseEncoding.base16().encode(pbArray);

		}

		/// <summary>
		/// Decode Base32 strings according to RFC 4648.
		/// </summary>
		public static byte[] ParseBase32(String str)
		{
			if((str == null) || ((str.length() % 8) != 0))
			{
				assert false;
				return null;
			}
            return BaseEncoding.base32().decode(str);

		}

		/// <summary>
		/// Set all bytes in a byte array to zero.
		/// </summary>
		/// <param name="pbArray">Input array. All bytes of this array will be set
		/// to zero.</param>
		public static void ZeroByteArray(byte[] pbArray)
		{
			assert pbArray != null;
			if(pbArray == null) throw new IllegalArgumentException("pbArray");

			// for(int i = 0; i < pbArray.Length; ++i)
			//	pbArray[i] = 0;

			Arrays.fill(pbArray, (byte)0);
		}

		/// <summary>
		/// Convert 2 bytes to a 16-bit unsigned integer using Little-Endian
		/// encoding.
		/// </summary>
		/// <param name="pb">Input bytes. Array must contain at least 2 bytes.</param>
		/// <returns>16-bit unsigned integer.</returns>
		public static short BytesToUInt16(byte[] pb)
		{
			assert (pb != null) && (pb.length == 2);
			if(pb == null) throw new IllegalArgumentException("pb");
			if(pb.length != 2) throw new IllegalArgumentException();

			return (short)(bint(pb[0]) | (bint(pb[1]) << 8));
		}

		/// <summary>
		/// Convert 4 bytes to a 32-bit unsigned integer using Little-Endian
		/// encoding.
		/// </summary>
		/// <param name="pb">Input bytes.</param>
		/// <returns>32-bit unsigned integer.</returns>
		public static int BytesToUInt32(byte[] pb)
		{
			assert (pb != null) && (pb.length == 4);
			if(pb == null) throw new IllegalArgumentException("pb");
			if(pb.length != 4) throw new IllegalArgumentException("Input array must contain 4 bytes!");

			return bint(pb[0]) | (bint(pb[1]) << 8) | (bint(pb[2]) << 16) |
				(bint(pb[3]) << 24);
		}

        public static int bint(byte b) {
            return b & 0xff;
        }

		/// <summary>
		/// Convert 8 bytes to a 64-bit unsigned integer using Little-Endian
		/// encoding.
		/// </summary>
		/// <param name="pb">Input bytes.</param>
		/// <returns>64-bit unsigned integer.</returns>
		public static long BytesToUInt64(byte[] pb)
		{
			assert (pb != null) && (pb.length == 8);
			if(pb == null) throw new IllegalArgumentException("pb");
			if(pb.length != 8) throw new IllegalArgumentException();

			return (long)bint(pb[0]) | ((long)bint(pb[1]) << 8) | ((long)bint(pb[2]) << 16) |
				((long)(pb[3]) << 24) | ((long)bint(pb[4]) << 32) | ((long)bint(pb[5]) << 40) |
				((long)bint(pb[6]) << 48) | ((long)bint(pb[7]) << 56);
		}

		/// <summary>
		/// Convert a 16-bit unsigned integer to 2 bytes using Little-Endian
		/// encoding.
		/// </summary>
		/// <param name="uValue">16-bit input word.</param>
		/// <returns>Two bytes representing the 16-bit value.</returns>
		public static byte[] UInt16ToBytes(short uValue)
		{
			byte[] pb = new byte[2];

				pb[0] = (byte)uValue;
				pb[1] = (byte)(uValue >> 8);

			return pb;
		}

		/// <summary>
		/// Convert a 32-bit unsigned integer to 4 bytes using Little-Endian
		/// encoding.
		/// </summary>
		/// <param name="uValue">32-bit input word.</param>
		/// <returns>Four bytes representing the 32-bit value.</returns>
		public static byte[] UInt32ToBytes(int uValue)
		{
			byte[] pb = new byte[4];

				pb[0] = (byte)uValue;
				pb[1] = (byte)(uValue >> 8);
				pb[2] = (byte)(uValue >> 16);
				pb[3] = (byte)(uValue >> 24);

			return pb;
		}

		/// <summary>
		/// Convert a 64-bit unsigned integer to 8 bytes using Little-Endian
		/// encoding.
		/// </summary>
		/// <param name="uValue">64-bit input word.</param>
		/// <returns>Eight bytes representing the 64-bit value.</returns>
		public static byte[] UInt64ToBytes(long uValue)
		{
			byte[] pb = new byte[8];

				pb[0] = (byte)uValue;
				pb[1] = (byte)(uValue >> 8);
				pb[2] = (byte)(uValue >> 16);
				pb[3] = (byte)(uValue >> 24);
				pb[4] = (byte)(uValue >> 32);
				pb[5] = (byte)(uValue >> 40);
				pb[6] = (byte)(uValue >> 48);
				pb[7] = (byte)(uValue >> 56);

			return pb;
		}

		public static boolean ArraysEqual(byte[] x, byte[] y)
		{
			// Return false if one of them is null (not comparable)!
			if((x == null) || (y == null)) { assert false; return false; }

			if(x.length != y.length) return false;

			for(int i = 0; i < x.length; ++i)
			{
				if(x[i] != y[i]) return false;
			}

			return true;
		}

		public static void XorArray(byte[] pbSource, int nSourceOffset,
			byte[] pbBuffer, int nBufferOffset, int nLength)
		{
			if(pbSource == null) throw new IllegalArgumentException("pbSource");
			if(nSourceOffset < 0) throw new IllegalArgumentException();
			if(pbBuffer == null) throw new IllegalArgumentException("pbBuffer");
			if(nBufferOffset < 0) throw new IllegalArgumentException();
			if(nLength < 0) throw new IllegalArgumentException();
			if((nSourceOffset + nLength) > pbSource.length) throw new IllegalArgumentException();
			if((nBufferOffset + nLength) > pbBuffer.length) throw new IllegalArgumentException();

			for(int i = 0; i < nLength; ++i)
				pbBuffer[nBufferOffset + i] ^= pbSource[nSourceOffset + i];
		}

		/// <summary>
		/// Fast hash that can be used e.g. for hash tables.
		/// The algorithm might change in the future; do not store
		/// the hashes for later use.
		/// </summary>
		public static int Hash32(byte[] v, int iStart, int iLength)
		{
			int u = 0x326F637B;

			if(v == null) { assert false; return u; }
			if(iStart < 0) { assert false; return u; }
			if(iLength < 0) { assert false; return u; }

			int m = iStart + iLength;
			if(m > v.length) { assert false; return u; }

			for(int i = iStart; i < m; ++i)
			{
				u ^= m_vSBox[bint(v[i])];
				u *= 3;
			}

			return u;
		}

		public static void CopyStream(InputStream sSource, OutputStream sTarget)
                throws IOException
		{
			assert (sSource != null && (sTarget != null));
			if(sSource == null) throw new IllegalArgumentException("sSource");
			if(sTarget == null) throw new IllegalArgumentException("sTarget");

			final int nBufSize = 4096;
			byte[] pbBuf = new byte[nBufSize];

            int read;
			while((read = sSource.read(pbBuf, 0, nBufSize)) != -1)
			{
				sTarget.write(pbBuf, 0, read);
			}

			// Do not close any of the streams
		}

		public static byte[] Read(InputStream s, int nCount) throws IOException
		{
			if(s == null) throw new IllegalArgumentException("s");
			if(nCount < 0) throw new ArrayIndexOutOfBoundsException("nCount");

			byte[] pb = new byte[nCount];
			int iOffset = 0;
			while(nCount > 0)
			{
				int iRead = s.read(pb, iOffset, nCount);
				if(iRead == -1) break;

				iOffset += iRead;
				nCount -= iRead;
			}

			if(iOffset != pb.length)
			{
				byte[] pbPart = new byte[iOffset];
				System.arraycopy(pb, 0, pbPart, 0, iOffset);
				return pbPart;
			}

			return pb;
		}

		public static void Write(OutputStream s, byte[] pbData) throws IOException
		{
			if(s == null) { assert false; return; }
			if(pbData == null) { assert false; return; }

			s.write(pbData, 0, pbData.length);
		}

		public static byte[] Compress(byte[] pbData) throws IOException
		{
			if(pbData == null) throw new IllegalArgumentException("pbData");
			if(pbData.length == 0) return pbData;

			ByteArrayOutputStream msCompressed = new ByteArrayOutputStream();
			GZIPOutputStream gz = null;
			ByteArrayInputStream msSource = new ByteArrayInputStream(pbData);
			try {
				gz = new GZIPOutputStream(msCompressed);
				MemUtil.CopyStream(msSource, gz);
			} finally {
				if (gz != null)
                    gz.close();
			}

			byte[] pbCompressed = msCompressed.toByteArray();
			msCompressed.close();
			return pbCompressed;
		}

		public static byte[] Decompress(byte[] pbCompressed) throws IOException
		{
			if(pbCompressed == null) throw new IllegalArgumentException("pbCompressed");
			if(pbCompressed.length == 0) return pbCompressed;

			ByteArrayInputStream msCompressed = new ByteArrayInputStream(pbCompressed);
			GZIPInputStream gz = null;
			ByteArrayOutputStream msData = new ByteArrayOutputStream();
			try {
				gz = new GZIPInputStream(msCompressed);
				MemUtil.CopyStream(gz, msData);
			} finally {
				if (gz != null)
					gz.close();
			}
			msCompressed.close();

			byte[] pbData = msData.toByteArray();
			msData.close();
			return pbData;
		}

		public static <T> int IndexOf(T[] vHaystack, T[] vNeedle)
		{
			if(vHaystack == null) throw new IllegalArgumentException("vHaystack");
			if(vNeedle == null) throw new IllegalArgumentException("vNeedle");
			if(vNeedle.length == 0) return 0;

			for(int i = 0; i <= (vHaystack.length - vNeedle.length); ++i)
			{
				boolean bFound = true;
				for(int m = 0; m < vNeedle.length; ++m)
				{
					if(!vHaystack[i + m].equals(vNeedle[m]))
					{
						bFound = false;
						break;
					}
				}
				if(bFound) return i;
			}

			return -1;
		}

		public static <T> T[] Mid(Class<T> clazz, T[] v, int iOffset, int iLength)
		{
			if(v == null) throw new IllegalArgumentException("v");
			if(iOffset < 0) throw new ArrayIndexOutOfBoundsException("iOffset");
			if(iLength < 0) throw new ArrayIndexOutOfBoundsException("iLength");
			if((iOffset + iLength) > v.length) throw new IllegalArgumentException();

			T[] r = (T[]) Array.newInstance(clazz, iLength);
			System.arraycopy(v, iOffset, r, 0, iLength);
			return r;
		}
        public static byte[] Mid(byte[] v, int iOffset, int iLength)
        {
            if(v == null) throw new IllegalArgumentException("v");
            if(iOffset < 0) throw new ArrayIndexOutOfBoundsException("iOffset");
            if(iLength < 0) throw new ArrayIndexOutOfBoundsException("iLength");
            if((iOffset + iLength) > v.length) throw new IllegalArgumentException();

            byte[] r = new byte[iLength];
            System.arraycopy(v, iOffset, r, 0, iLength);
            return r;
        }

		public static <T> Iterable<T> Union(Iterable<T> a, Iterable<T> b)
		{
			if(a == null) throw new IllegalArgumentException("a");
			if(b == null) throw new IllegalArgumentException("b");

			Map<T, Boolean> d = Maps.newHashMap();

			for(T ta : a)
			{
				if(d.containsKey(ta)) continue; // Prevent duplicates

				d.put(ta, true);
			}

			for(T tb : b)
			{
				if(d.containsKey(tb)) continue; // Prevent duplicates

				d.put(tb, true);
			}

            return d.keySet();
		}

		public static <T> Iterable<T> Intersect(Iterable<T> a, Iterable<T> b)
		{
			if(a == null) throw new IllegalArgumentException("a");
			if(b == null) throw new IllegalArgumentException("b");

            return Sets.intersection(Sets.newHashSet(a), Sets.newHashSet(b));
		}

		public static <T> Iterable<T> Except(Iterable<T> a, Iterable<T> b)
		{
			if(a == null) throw new IllegalArgumentException("a");
			if(b == null) throw new IllegalArgumentException("b");
            List<T> all = Lists.newArrayList(a);
            for (T bs : b) all.remove(bs);
            return all;
		}
	}
