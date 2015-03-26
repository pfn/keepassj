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

import java.util.*;

/// <summary>
	/// A list of <c>ProtectedString</c> objects (dictionary).
	/// </summary>
	public class ProtectedStringDictionary implements
		IDeepCloneable<ProtectedStringDictionary>,
		Iterable<Map.Entry<String, ProtectedString>>
	{
		private SortedMap<String, ProtectedString> m_vStrings = new TreeMap<String, ProtectedString>();

		/// <summary>
		/// Get the number of strings in this entry.
		/// </summary>
		public int getUCount()
		{
			return m_vStrings.size();
		}

		/// <summary>
		/// Construct a new list of protected strings.
		/// </summary>
		public ProtectedStringDictionary()
		{
		}

		public Iterator<Map.Entry<String,ProtectedString>> iterator()
		{
			return m_vStrings.entrySet().iterator();
		}

		public void Clear()
		{
			m_vStrings.clear();
		}

		/// <summary>
		/// Clone the current <c>ProtectedStringList</c> object, including all
		/// stored protected strings.
		/// </summary>
		/// <returns>New <c>ProtectedStringList</c> object.</returns>
		public ProtectedStringDictionary CloneDeep()
		{
			ProtectedStringDictionary plNew = new ProtectedStringDictionary();

			for(Map.Entry<String, ProtectedString> kvpStr : m_vStrings.entrySet())
			{
				// ProtectedString objects are immutable
				plNew.Set(kvpStr.getKey(), kvpStr.getValue());
			}

			return plNew;
		}

		@Deprecated
		public boolean EqualsDictionary(ProtectedStringDictionary dict)
		{
			return EqualsDictionary(dict, PwCompareOptions.or(PwCompareOptions.None), MemProtCmpMode.None);
		}

		@Deprecated
		public boolean EqualsDictionary(ProtectedStringDictionary dict,
			MemProtCmpMode mpCompare)
		{
			return EqualsDictionary(dict, PwCompareOptions.or(PwCompareOptions.None), mpCompare);
		}

		public boolean EqualsDictionary(ProtectedStringDictionary dict,
			PwCompareOptions.Options pwOpt, MemProtCmpMode mpCompare)
		{
			if(dict == null) { assert false; return false; }

			boolean bNeEqStd = pwOpt.contains(PwCompareOptions.NullEmptyEquivStd);
			if(!bNeEqStd)
			{
				if(m_vStrings.size() != dict.m_vStrings.size()) return false;
			}

			for(Map.Entry<String, ProtectedString> kvp : m_vStrings.entrySet())
			{
				boolean bStdField = PwDefs.IsStandardField(kvp.getKey());
				ProtectedString ps = dict.Get(kvp.getKey());

				if(bNeEqStd && (ps == null) && bStdField)
					ps = ProtectedString.Empty;

				if(ps == null) return false;

				if(mpCompare == MemProtCmpMode.Full)
				{
					if(ps.isProtected() != kvp.getValue().isProtected()) return false;
				}
				else if(mpCompare == MemProtCmpMode.CustomOnly)
				{
					if(!bStdField && (ps.isProtected() != kvp.getValue().isProtected()))
						return false;
				}

				if(!ps.ReadString().equals(kvp.getValue().ReadString())) return false;
			}

			if(bNeEqStd)
			{
				for(Map.Entry<String, ProtectedString> kvp : dict.m_vStrings.entrySet())
				{
					ProtectedString ps = Get(kvp.getKey());

					if(ps != null) continue; // Compared previously
					if(!PwDefs.IsStandardField(kvp.getKey())) return false;
					if(!kvp.getValue().isEmpty()) return false;
				}
			}

			return true;
		}

		/// <summary>
		/// Get one of the protected strings.
		/// </summary>
		/// <param name="strName">String identifier.</param>
		/// <returns>Protected String. If the String identified by
		/// <paramref name="strName" /> cannot be found, the function
		/// returns <c>null</c>.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input parameter
		/// is <c>null</c>.</exception>
		public ProtectedString Get(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			ProtectedString ps;
            return m_vStrings.get(strName);
		}

		/// <summary>
		/// Get one of the protected strings. The return value is never <c>null</c>.
		/// If the requested String cannot be found, an empty protected String
		/// object is returned.
		/// </summary>
		/// <param name="strName">String identifier.</param>
		/// <returns>Returns a protected String object. If the standard String
		/// has not been set yet, the return value is an empty String (<c>""</c>).</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public ProtectedString GetSafe(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			ProtectedString ps;
            if (!m_vStrings.containsKey(strName))
                return ProtectedString.Empty;
            return m_vStrings.get(strName);
		}

		/// <summary>
		/// Test if a named String exists.
		/// </summary>
		/// <param name="strName">Name of the String to try.</param>
		/// <returns>Returns <c>true</c> if the String exists, otherwise <c>false</c>.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if
		/// <paramref name="strName" /> is <c>null</c>.</exception>
		public boolean Exists(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			return m_vStrings.containsKey(strName);
		}

		/// <summary>
		/// Get one of the protected strings. If the String doesn't exist, the
		/// return value is an empty String (<c>""</c>).
		/// </summary>
		/// <param name="strName">Name of the requested String.</param>
		/// <returns>Requested String value or an empty String, if the named
		/// String doesn't exist.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public String ReadSafe(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			ProtectedString ps;
            if (!m_vStrings.containsKey(strName))
                return "";
            return m_vStrings.get(strName).ReadString();
		}

		/// <summary>
		/// Get one of the entry strings. If the String doesn't exist, the
		/// return value is an empty String (<c>""</c>). If the String is
		/// in-memory protected, the return value is <c>PwDefs.HiddenPassword</c>.
		/// </summary>
		/// <param name="strName">Name of the requested String.</param>
		/// <returns>Returns the requested String in plain-text or
		/// <c>PwDefs.HiddenPassword</c> if the String cannot be found.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public String ReadSafeEx(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			ProtectedString ps = m_vStrings.get(strName);
			if(ps != null)
			{
				if(ps.isProtected()) return PwDefs.HiddenPassword;
				return ps.ReadString();
			}

			return "";
		}

		/// <summary>
		/// Set a String.
		/// </summary>
		/// <param name="strField">Identifier of the String field to modify.</param>
		/// <param name="psNewValue">New value. This parameter must not be <c>null</c>.</param>
		/// <exception cref="System.IllegalArgumentException">Thrown if one of the input
		/// parameters is <c>null</c>.</exception>
		public void Set(String strField, ProtectedString psNewValue)
		{
			assert strField != null; if(strField == null) throw new IllegalArgumentException("strField");
			assert psNewValue != null; if(psNewValue == null) throw new IllegalArgumentException("psNewValue");

			m_vStrings.put(strField, psNewValue);
		}

		/// <summary>
		/// Delete a String.
		/// </summary>
		/// <param name="strField">Name of the String field to delete.</param>
		/// <returns>Returns <c>true</c> if the field has been successfully
		/// removed, otherwise the return value is <c>false</c>.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public boolean Remove(String strField)
		{
			assert strField != null; if(strField == null) throw new IllegalArgumentException("strField");

			return m_vStrings.remove(strField) != null;
		}

		public List<String> GetKeys()
		{
			List<String> v = new ArrayList<String>();

			for(String strKey : m_vStrings.keySet()) v.add(strKey);

			return v;
		}

		public void EnableProtection(String strField, boolean bProtect)
		{
			ProtectedString ps = Get(strField);
			if(ps == null) return; // Nothing to do, no assert

			if(ps.isProtected() != bProtect)
			{
				byte[] pbData = ps.ReadUtf8();
				Set(strField, new ProtectedString(bProtect, pbData));
				MemUtil.ZeroByteArray(pbData);
			}
		}
	}
