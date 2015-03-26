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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PwCharSet
	{
		public final static String UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		public final static String LowerCase = "abcdefghijklmnopqrstuvwxyz";
		public final static String Digits = "0123456789";

		public final static String UpperConsonants = "BCDFGHJKLMNPQRSTVWXYZ";
		public final static String LowerConsonants = "bcdfghjklmnpqrstvwxyz";
		public final static String UpperVowels = "AEIOU";
		public final static String LowerVowels = "aeiou";

		public final static String Punctuation = ",.;:";
		public final static String Brackets = "[]{}()<>";

		public final static String PrintableAsciiSpecial = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

		public final static String UpperHex = "0123456789ABCDEF";
		public final static String LowerHex = "0123456789abcdef";

		public final static String Invalid = "\t\r\n";
		public final static String LookAlike = "O0l1I|";

		final static String MenuAccels = PwCharSet.LowerCase + PwCharSet.Digits;

		private final static int CharTabSize = (0x10000 / 8);

		private List<Character> m_vChars = new ArrayList<Character>();
		private byte[] m_vTab = new byte[CharTabSize];

		private static String m_strHighAnsi = null;
		public static String getHighAnsiChars()
		{
            if(m_strHighAnsi == null) { new PwCharSet(); } // Create String
            assert m_strHighAnsi != null;
            return m_strHighAnsi;
        }

		private static String m_strSpecial = null;
		public static String getSpecialChars()
		{
            if(m_strSpecial == null) { new PwCharSet(); } // Create String
            assert m_strSpecial != null;
            return m_strSpecial;
        }

		/// <summary>
		/// Create a new, empty character set collection object.
		/// </summary>
		public PwCharSet()
		{
			Initialize(true);
		}

		public PwCharSet(String strCharSet)
		{
			Initialize(true);
			Add(strCharSet);
		}

		private PwCharSet(boolean bFullInitialize)
		{
			Initialize(bFullInitialize);
		}

		private void Initialize(boolean bFullInitialize)
		{
			Clear();

			if(!bFullInitialize) return;

			if(m_strHighAnsi == null)
			{
				StringBuilder sbHighAnsi = new StringBuilder();
				// [U+0080, U+009F] are C1 control characters,
				// U+00A0 is non-breaking space
				for(char ch = '\u00A1'; ch <= '\u00AC'; ++ch)
					sbHighAnsi.append(ch);
				// U+00AD is soft hyphen (format character)
				for(char ch = '\u00AE'; ch < '\u00FF'; ++ch)
					sbHighAnsi.append(ch);
				sbHighAnsi.append('\u00FF');

				m_strHighAnsi = sbHighAnsi.toString();
			}

			if(m_strSpecial == null)
			{
				PwCharSet pcs = new PwCharSet(false);
				pcs.AddRange('!', '/');
				pcs.AddRange(':', '@');
				pcs.AddRange('[', '`');
				pcs.Add("|~");
				pcs.Remove("-_ ");
				pcs.Remove(PwCharSet.Brackets);

				m_strSpecial = pcs.toString();
			}
		}

		/// <summary>
		/// Number of characters in this set.
		/// </summary>
		public int Size()
		{
			return m_vChars.size();
		}

		/// <summary>
		/// Get a character of the set using an index.
		/// </summary>
		/// <param name="uPos">Index of the character to get.</param>
		/// <returns>Character at the specified position. If the index is invalid,
		/// an <c>ArrayIndexOutOfBoundsException</c> is thrown.</returns>
		public char get(int uPos)
		{
            if(uPos >= m_vChars.size())
                throw new ArrayIndexOutOfBoundsException("uPos");

            return m_vChars.get(uPos);
    }

		/// <summary>
		/// Remove all characters from this set.
		/// </summary>
		public void Clear()
		{
			m_vChars.clear();
			Arrays.fill(m_vTab, (byte)0);
		}

		public boolean Contains(char ch)
		{
			return (((m_vTab[ch / 8] >> (ch % 8)) & 1) != Character.MIN_VALUE);
		}

		public boolean Contains(String strCharacters)
		{
			assert strCharacters != null;
			if(strCharacters == null) throw new IllegalArgumentException("strCharacters");

			for(char ch : strCharacters.toCharArray())
			{
				if(!Contains(ch)) return false;
			}

			return true;
		}

		/// <summary>
		/// Add characters to the set.
		/// </summary>
		/// <param name="ch">Character to add.</param>
		public void Add(char ch)
		{
			if(ch == Character.MIN_VALUE) { assert false; return; }

			if(!Contains(ch))
			{
				m_vChars.add(ch);
				m_vTab[ch / 8] |= (byte)(1 << (ch % 8));
			}
		}

		/// <summary>
		/// Add characters to the set.
		/// </summary>
		/// <param name="strCharSet">String containing characters to add.</param>
		public void Add(String strCharSet)
		{
			assert strCharSet != null;
			if(strCharSet == null) throw new IllegalArgumentException("strCharSet");

			for(char ch : strCharSet.toCharArray())
				Add(ch);
		}

		public void Add(String strCharSet1, String strCharSet2)
		{
			Add(strCharSet1);
			Add(strCharSet2);
		}

		public void Add(String strCharSet1, String strCharSet2, String strCharSet3)
		{
			Add(strCharSet1);
			Add(strCharSet2);
			Add(strCharSet3);
		}

		public void AddRange(char chMin, char chMax)
		{

			for(char ch = chMin; ch < chMax; ++ch)
				Add(ch);

			Add(chMax);
		}

		public boolean AddCharSet(char chCharSetIdentifier)
		{
			boolean bResult = true;

			switch(chCharSetIdentifier)
			{
				case 'a': Add(PwCharSet.LowerCase, PwCharSet.Digits); break;
				case 'A': Add(PwCharSet.LowerCase, PwCharSet.UpperCase,
					PwCharSet.Digits); break;
				case 'U': Add(PwCharSet.UpperCase, PwCharSet.Digits); break;
				case 'c': Add(PwCharSet.LowerConsonants); break;
				case 'C': Add(PwCharSet.LowerConsonants,
					PwCharSet.UpperConsonants); break;
				case 'z': Add(PwCharSet.UpperConsonants); break;
				case 'd': Add(PwCharSet.Digits); break; // Digit
				case 'h': Add(PwCharSet.LowerHex); break;
				case 'H': Add(PwCharSet.UpperHex); break;
				case 'l': Add(PwCharSet.LowerCase); break;
				case 'L': Add(PwCharSet.LowerCase, PwCharSet.UpperCase); break;
				case 'u': Add(PwCharSet.UpperCase); break;
				case 'p': Add(PwCharSet.Punctuation); break;
				case 'b': Add(PwCharSet.Brackets); break;
				case 's': Add(PwCharSet.PrintableAsciiSpecial); break;
				case 'S': Add(PwCharSet.UpperCase, PwCharSet.LowerCase);
					Add(PwCharSet.Digits, PwCharSet.PrintableAsciiSpecial); break;
				case 'v': Add(PwCharSet.LowerVowels); break;
				case 'V': Add(PwCharSet.LowerVowels, PwCharSet.UpperVowels); break;
				case 'Z': Add(PwCharSet.UpperVowels); break;
				case 'x': Add(m_strHighAnsi); break;
				default: bResult = false; break;
			}

			return bResult;
		}

		public boolean Remove(char ch)
		{
			m_vTab[ch / 8] &= (byte)(~(1 << (ch % 8)));
			return m_vChars.remove(ch) != null;
		}

		public boolean Remove(String strCharacters)
		{
			assert strCharacters != null;
			if(strCharacters == null) throw new IllegalArgumentException("strCharacters");

			boolean bResult = true;
			for(char ch : strCharacters.toCharArray())
			{
				if(!Remove(ch)) bResult = false;
			}

			return bResult;
		}

		public boolean RemoveIfAllExist(String strCharacters)
		{
			assert strCharacters != null;
			if(strCharacters == null) throw new IllegalArgumentException("strCharacters");

			if(!Contains(strCharacters))
				return false;

			return Remove(strCharacters);
		}

		/// <summary>
		/// Convert the character set to a String containing all its characters.
		/// </summary>
		/// <returns>String containing all character set characters.</returns>
		public String toString()
		{
			StringBuilder sb = new StringBuilder();
			for(char ch : m_vChars)
				sb.append(ch);

			return sb.toString();
		}

		public String PackAndRemoveCharRanges()
		{
			StringBuilder sb = new StringBuilder();

			sb.append(RemoveIfAllExist(PwCharSet.UpperCase) ? 'U' : '_');
			sb.append(RemoveIfAllExist(PwCharSet.LowerCase) ? 'L' : '_');
			sb.append(RemoveIfAllExist(PwCharSet.Digits) ? 'D' : '_');
			sb.append(RemoveIfAllExist(m_strSpecial) ? 'S' : '_');
			sb.append(RemoveIfAllExist(PwCharSet.Punctuation) ? 'P' : '_');
			sb.append(RemoveIfAllExist("-") ? 'm' : '_');
			sb.append(RemoveIfAllExist("_") ? 'u' : '_');
			sb.append(RemoveIfAllExist(" ") ? 's' : '_');
			sb.append(RemoveIfAllExist(PwCharSet.Brackets) ? 'B' : '_');
			sb.append(RemoveIfAllExist(m_strHighAnsi) ? 'H' : '_');

			return sb.toString();
		}

		public void UnpackCharRanges(String strRanges)
		{
			if(strRanges == null) { assert false; return; }
			if(strRanges.length() < 10) { assert false; return; }
            char[] cs = strRanges.toCharArray();

			if(cs[0] != '_') Add(PwCharSet.UpperCase);
			if(cs[1] != '_') Add(PwCharSet.LowerCase);
			if(cs[2] != '_') Add(PwCharSet.Digits);
			if(cs[3] != '_') Add(m_strSpecial);
			if(cs[4] != '_') Add(PwCharSet.Punctuation);
			if(cs[5] != '_') Add('-');
			if(cs[6] != '_') Add('_');
			if(cs[7] != '_') Add(' ');
			if(cs[8] != '_') Add(PwCharSet.Brackets);
			if(cs[9] != '_') Add(m_strHighAnsi);
		}
	}
