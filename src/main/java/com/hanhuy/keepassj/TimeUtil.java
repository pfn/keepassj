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
import com.google.common.base.Strings;

import java.text.SimpleDateFormat;
import java.util.*;

/// <summary>
	/// Contains various static time structure manipulation and conversion
	/// routines.
	/// </summary>
	public class TimeUtil
	{
		/// <summary>
		/// Length of a compressed <c>PW_TIME</c> structure in bytes.
		/// </summary>
		public static final int PwTimeLength = 7;

		private static String m_strDtfStd = null;
		private static String m_strDtfDate = null;

		/// <summary>
		/// Pack a <c>Date</c> object into 5 bytes. Layout: 2 zero bits,
		/// year 12 bits, month 4 bits, day 5 bits, hour 5 bits, minute 6
		/// bits, second 6 bits.
		/// </summary>
		/// <param name="dt"></param>
		/// <returns></returns>
		public static byte[] PackTime(Date dt)
		{
			byte[] pb = new byte[5];

			// Pack time to 5 byte structure:
			// Byte bits: 11111111 22222222 33333333 44444444 55555555
			// Contents : 00YYYYYY YYYYYYMM MMDDDDDH HHHHMMMM MMSSSSSS
            Calendar c = Calendar.getInstance();
            c.setTime(dt);
			pb[0] = (byte)((c.get(Calendar.YEAR) >> 6) & 0x3F);
			pb[1] = (byte)(((c.get(Calendar.YEAR) & 0x3F) << 2) | ((c.get(Calendar.MONTH) >> 2) & 0x03));
			pb[2] = (byte)(((c.get(Calendar.MONTH) & 0x03) << 6) | ((c.get(Calendar.DAY_OF_MONTH) & 0x1F) << 1) |
				((c.get(Calendar.HOUR_OF_DAY) >> 4) & 0x01));
			pb[3] = (byte)(((c.get(Calendar.HOUR_OF_DAY) & 0x0F) << 4) | ((c.get(Calendar.MINUTE) >> 2) & 0x0F));
			pb[4] = (byte)(((c.get(Calendar.MINUTE) & 0x03) << 6) | (c.get(Calendar.SECOND) & 0x3F));

			return pb;
		}

		/// <summary>
		/// Unpack a packed time (5 bytes, packed by the <c>PackTime</c>
		/// member function) to a <c>Date</c> object.
		/// </summary>
		/// <param name="pb">Packed time, 5 bytes.</param>
		/// <returns>Unpacked <c>Date</c> object.</returns>
		public static Date UnpackTime(byte[] pb)
		{
			assert (pb != null && (pb.length == 5));
			if(pb == null) throw new IllegalArgumentException("pb");
			if(pb.length != 5) throw new IllegalArgumentException();

			int n1 = pb[0], n2 = pb[1], n3 = pb[2], n4 = pb[3], n5 = pb[4];

			// Unpack 5 byte structure to date and time
			int nYear = (n1 << 6) | (n2 >> 2);
			int nMonth = ((n2 & 0x00000003) << 2) | (n3 >> 6);
			int nDay = (n3 >> 1) & 0x0000001F;
			int nHour = ((n3 & 0x00000001) << 4) | (n4 >> 4);
			int nMinute = ((n4 & 0x0000000F) << 2) | (n5 >> 6);
			int nSecond = n5 & 0x0000003F;

			return new Date(nYear, nMonth, nDay, nHour, nMinute, nSecond);
		}

		/// <summary>
		/// Pack a <c>Date</c> object into 7 bytes (<c>PW_TIME</c>).
		/// </summary>
		/// <param name="dt">Object to be encoded.</param>
		/// <returns>Packed time, 7 bytes (<c>PW_TIME</c>).</returns>
		public static byte[] PackPwTime(Date dt)
		{
			assert PwTimeLength == 7;

            Calendar c = Calendar.getInstance();
			byte[] pb = new byte[7];
			pb[0] = (byte)(c.get(Calendar.YEAR) & 0xFF);
			pb[1] = (byte)(c.get(Calendar.YEAR) >> 8);
			pb[2] = (byte)c.get(Calendar.MONTH);
			pb[3] = (byte)c.get(Calendar.DAY_OF_MONTH);
			pb[4] = (byte)c.get(Calendar.HOUR_OF_DAY);
			pb[5] = (byte)c.get(Calendar.MINUTE);
			pb[6] = (byte)c.get(Calendar.SECOND);

			return pb;
		}

		/// <summary>
		/// Unpack a packed time (7 bytes, <c>PW_TIME</c>) to a <c>Date</c> object.
		/// </summary>
		/// <param name="pb">Packed time, 7 bytes.</param>
		/// <returns>Unpacked <c>Date</c> object.</returns>
		public static Date UnpackPwTime(byte[] pb)
		{
			assert PwTimeLength == 7;

			assert pb != null; if(pb == null) throw new IllegalArgumentException("pb");
			assert pb.length == 7; if(pb.length != 7) throw new IllegalArgumentException();

            Calendar c = Calendar.getInstance();
            c.set(Calendar.YEAR, (pb[1] << 8) | pb[0]);
            c.set(Calendar.MONTH, pb[2]);
            c.set(Calendar.DAY_OF_MONTH, pb[3]);
            c.set(Calendar.HOUR_OF_DAY, pb[4]);
            c.set(Calendar.MINUTE, pb[5]);
            c.set(Calendar.SECOND, pb[6]);
            return c.getTime();
		}

		/// <summary>
		/// Convert a <c>Date</c> object to a displayable String.
		/// </summary>
		/// <param name="dt"><c>Date</c> object to convert to a String.</param>
		/// <returns>String representing the specified <c>Date</c> object.</returns>
		public static String ToDisplayString(Date dt)
		{
			return dt.toString();
		}

		public static String ToDisplayStringDateOnly(Date dt)
		{
            return SimpleDateFormat.getDateInstance().format(dt);
		}

		public static Date FromDisplayString(String strDisplay)
		{
			Date dt;

			try { dt = SimpleDateFormat.getInstance().parse(strDisplay); return dt; }
			catch(Exception e) { }

			assert false;
			return new Date();
		}

		private static String DeriveCustomFormat(String strDT, Date dt)
		{
			String[] vPlh = new String[] {
				// Names, sorted by length
				"MMMM", "dddd",
				"MMM", "ddd",
				"gg", "g",

				// Numbers, the ones with prefix '0' first
				"yyyy", "yyy", "yy", "y",
				"MM", "M",
				"dd", "d",
				"HH", "hh", "H", "h",
				"mm", "m",
				"ss", "s",

				"tt", "t"
			};

			List<String> lValues = new ArrayList<String>();
			for(String strPlh : vPlh)
			{
				String strEval = strPlh;
				if(strEval.length() == 1) strEval = "%" + strPlh; // Make custom

				lValues.add(new SimpleDateFormat(strEval).format(dt));
			}

			StringBuilder sbAll = new StringBuilder();
			sbAll.append("dfFghHKmMstyz:/\"\'\\%");
			sbAll.append(strDT);
			for(String strVEnum : lValues) { sbAll.append(strVEnum); }

			List<Character> lCodes = new ArrayList<Character>();
			for(int i = 0; i < vPlh.length; ++i)
			{
				char ch = StrUtil.GetUnusedChar(sbAll.toString());
				lCodes.add(ch);
				sbAll.append(ch);
			}

			String str = strDT;
			for(int i = 0; i < vPlh.length; ++i)
			{
				String strValue = lValues.get(i);
				if(Strings.isNullOrEmpty(strValue)) continue;

				str = str.replace(strValue, String.valueOf(lCodes.get(i)));
			}

			StringBuilder sbFmt = new StringBuilder();
			boolean bInLiteral = false;
			for(char ch : str.toCharArray())
			{
				int iCode = lCodes.indexOf(ch);

				// The escape character doesn't work correctly (e.g.
				// "dd\\.MM\\.yyyy\\ HH\\:mm\\:ss" doesn't work, but
				// "dd'.'MM'.'yyyy' 'HH':'mm':'ss" does); use '' instead

				// if(iCode >= 0) sbFmt.Append(vPlh[iCode]);
				// else // Literal
				// {
				//	sbFmt.Append('\\');
				//	sbFmt.Append(ch);
				// }

				if(iCode >= 0)
				{
					if(bInLiteral) { sbFmt.append('\''); bInLiteral = false; }
					sbFmt.append(vPlh[iCode]);
				}
				else // Literal
				{
					if(!bInLiteral) { sbFmt.append('\''); bInLiteral = true; }
					sbFmt.append(ch);
				}
			}
			if(bInLiteral) sbFmt.append('\'');

			return sbFmt.toString();
		}

		public static String SerializeUtc(Date dt)
		{
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            String str = sdf.format(dt);
			if(!str.endsWith("Z")) str += "Z";
			return str;
		}

		public static boolean TryDeserializeUtc(String str, Date[] dt)
		{
			if(str == null) throw new IllegalArgumentException("str");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

//			if(str.endsWith("Z")) str = str.substring(0, str.length() - 1);

            try {
                dt[0] = sdf.parse(str);
                return true;
            } catch (Exception e) {
                return false;
            }
		}

		public static Date ConvertUnixTime(double dtUnix)
		{
            return new Date((long)dtUnix * 1000);
		}

		private static String[] m_vUSMonths = null;
		/// <summary>
		/// Parse a US textual date String, like e.g. "January 02, 2012".
		/// </summary>
		public static Date ParseUSTextDate(String strDate)
		{
			if(strDate == null) { assert false; return null; }

			if(m_vUSMonths == null)
				m_vUSMonths = new String[]{ "January", "February", "March",
					"April", "May", "June", "July", "August", "September",
					"October", "November", "December" };

			String str = strDate.trim();
			for(int i = 0; i < m_vUSMonths.length; ++i)
			{
				if(str.toLowerCase().startsWith(m_vUSMonths[i].toLowerCase()))
				{
					str = str.substring(m_vUSMonths[i].length());
					String[] v = str.split("[,;]");
					if((v == null) || (v.length != 2)) return null;

					String strDay = v[0].trim().replace("^0+", "");
					int iDay, iYear;
                    try {
                        iDay = Integer.parseInt(strDay);
                        iYear = Integer.parseInt(v[1].trim());
                        return new Date(iYear, i + 1, iDay);
                    } catch (Exception e) {
                        return null;
                    }
				}
			}

			return null;
		}

		private static final Date m_dtInvMin =
			new Date(2999, 12, 27, 23, 59, 59);
		private static final Date m_dtInvMax =
			new Date(2999, 12, 29, 23, 59, 59);
		public static int Compare(Date dtA, Date dtB, boolean bUnkIsPast)
		{
			if(bUnkIsPast)
			{
				// 2999-12-28 23:59:59 in KeePass 1.x means 'unknown';
				// expect time zone corruption (twice)
				// boolean bInvA = ((dtA.Year == 2999) && (dtA.Month == 12) &&
				//	(dtA.Day >= 27) && (dtA.Day <= 29) && (dtA.Minute == 59) &&
				//	(dtA.Second == 59));
				// boolean bInvB = ((dtB.Year == 2999) && (dtB.Month == 12) &&
				//	(dtB.Day >= 27) && (dtB.Day <= 29) && (dtB.Minute == 59) &&
				//	(dtB.Second == 59));
				// Faster due to internal implementation of Date:
				boolean bInvA = ((dtA.getTime() >= m_dtInvMin.getTime()) && (dtA.getTime() <= m_dtInvMax.getTime()) &&
					(dtA.getMinutes() == 59) && (dtA.getSeconds() == 59));
				boolean bInvB = ((dtB.getTime() >= m_dtInvMin.getTime()) && (dtB.getTime() <= m_dtInvMax.getTime()) &&
					(dtB.getMinutes() == 59) && (dtB.getSeconds() == 59));

				if(bInvA) return (bInvB ? 0 : -1);
				if(bInvB) return 1;
			}

			return dtA.compareTo(dtB);
		}

		static int CompareLastMod(ITimeLogger tlA, ITimeLogger tlB,
			boolean bUnkIsPast)
		{
			if(tlA == null) { assert false; return ((tlB == null) ? 0 : -1); }
			if(tlB == null) { assert false; return 1; }

			return Compare(tlA.getLastModificationTime(), tlB.getLastModificationTime(),
				bUnkIsPast);
		}
	}
