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
import java.util.TreeMap;
import java.util.Map;

	public class StringDictionaryEx implements IDeepCloneable<StringDictionaryEx>,
		Iterable<Map.Entry<String, String>>
	{
		private TreeMap<String, String> m_vDict =
			new TreeMap<String, String>();

		public int getCount()
		{
			return m_vDict.size();
		}

		public StringDictionaryEx()
		{
		}

		public Iterator<Map.Entry<String,String>> iterator()
		{
			return m_vDict.entrySet().iterator();
		}

		public StringDictionaryEx CloneDeep()
		{
			StringDictionaryEx plNew = new StringDictionaryEx();

			for(Map.Entry<String, String> kvpStr : m_vDict.entrySet())
				plNew.Set(kvpStr.getKey(), kvpStr.getValue());

			return plNew;
		}

		public String Get(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			String s;
            return m_vDict.get(strName);
		}

		public boolean Exists(String strName)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			return m_vDict.containsKey(strName);
		}

		/// <summary>
		/// Set a String.
		/// </summary>
		/// <param name="strField">Identifier of the String field to modify.</param>
		/// <param name="strNewValue">New value. This parameter must not be <c>null</c>.</param>
		/// <exception cref="System.IllegalArgumentException">Thrown if one of the input
		/// parameters is <c>null</c>.</exception>
		public void Set(String strField, String strNewValue)
		{
			assert strField != null; if(strField == null) throw new IllegalArgumentException("strField");
			assert strNewValue != null; if(strNewValue == null) throw new IllegalArgumentException("strNewValue");

			m_vDict.put(strField, strNewValue);
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

			return m_vDict.remove(strField) != null;
		}
	}
