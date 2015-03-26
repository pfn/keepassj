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

import java.util.Iterator;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/// <summary>
	/// A list of <c>ProtectedBinary</c> objects (dictionary).
	/// </summary>
	public class ProtectedBinaryDictionary implements
		IDeepCloneable<ProtectedBinaryDictionary>,
		Iterable<Map.Entry<String, ProtectedBinary>>
	{
		private SortedMap<String, ProtectedBinary> m_vBinaries =
			new TreeMap<String, ProtectedBinary>();

		/// <summary>
		/// Get the number of binaries in this entry.
		/// </summary>
		public int getUCount()
		{
			return m_vBinaries.size();
		}

		/// <summary>
		/// Construct a new list of protected binaries.
		/// </summary>
		public ProtectedBinaryDictionary()
		{
		}

		public Iterator<Map.Entry<String,ProtectedBinary>> iterator()
		{
			return m_vBinaries.entrySet().iterator();
		}

		public void Clear()
		{
			m_vBinaries.clear();
		}

		/// <summary>
		/// Clone the current <c>ProtectedBinaryList</c> object, including all
		/// stored protected strings.
		/// </summary>
		/// <returns>New <c>ProtectedBinaryList</c> object.</returns>
		public ProtectedBinaryDictionary CloneDeep()
		{
			ProtectedBinaryDictionary plNew = new ProtectedBinaryDictionary();

			for(Map.Entry<String, ProtectedBinary> kvpBin : m_vBinaries.entrySet())
			{
				// ProtectedBinary objects are immutable
				plNew.Set(kvpBin.getKey(), kvpBin.getValue());
			}

			return plNew;
		}

		public boolean EqualsDictionary(ProtectedBinaryDictionary dict)
		{
			if(dict == null) { assert false; return false; }

			if(m_vBinaries.size() != dict.m_vBinaries.size()) return false;

			for(Map.Entry<String, ProtectedBinary> kvp : m_vBinaries.entrySet())
			{
				ProtectedBinary pb = dict.Get(kvp.getKey());
				if(pb == null) return false;
				if(!pb.Equals(kvp.getValue())) return false;
			}

			return true;
		}

		/// <summary>
		/// Get one of the stored binaries.
		/// </summary>
		/// <param name="strName">Binary identifier.</param>
		/// <returns>Protected binary. If the binary identified by
		/// <paramref name="strName" /> cannot be found, the function
		/// returns <c>null</c>.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input
		/// parameter is <c>null</c>.</exception>
		public ProtectedBinary Get(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			ProtectedBinary pb;
            return m_vBinaries.get(strName);
		}

		/// <summary>
		/// Set a binary object.
		/// </summary>
		/// <param name="strField">Identifier of the binary field to modify.</param>
		/// <param name="pbNewValue">New value. This parameter must not be <c>null</c>.</param>
		/// <exception cref="System.IllegalArgumentException">Thrown if any of the input
		/// parameters is <c>null</c>.</exception>
		public void Set(String strField, ProtectedBinary pbNewValue)
		{
			assert strField != null; if(strField == null) throw new IllegalArgumentException("strField");
			assert pbNewValue != null; if(pbNewValue == null) throw new IllegalArgumentException("pbNewValue");

			m_vBinaries.put(strField, pbNewValue);
		}

		/// <summary>
		/// Remove a binary object.
		/// </summary>
		/// <param name="strField">Identifier of the binary field to remove.</param>
		/// <returns>Returns <c>true</c> if the object has been successfully
		/// removed, otherwise <c>false</c>.</returns>
		/// <exception cref="System.IllegalArgumentException">Thrown if the input parameter
		/// is <c>null</c>.</exception>
		public boolean Remove(String strField)
		{
			assert strField != null; if(strField == null) throw new IllegalArgumentException("strField");

			return m_vBinaries.remove(strField) != null;
		}

		public String KeysToString()
		{
			if(m_vBinaries.size() == 0) return "";

			StringBuilder sb = new StringBuilder();
			for(Map.Entry<String, ProtectedBinary> kvp : m_vBinaries.entrySet())
			{
				if(sb.length() > 0) sb.append(", ");
				sb.append(kvp.getKey());
			}

			return sb.toString();
		}
	}
