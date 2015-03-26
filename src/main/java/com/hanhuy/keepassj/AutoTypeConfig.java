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
import java.util.List;

//[Flags]
	enum AutoTypeObfuscationOptions
	{
		None,
		UseClipboard
	}

	class AutoTypeAssociation implements
		IDeepCloneable<AutoTypeAssociation>
	{
		private String m_strWindow = "";
		public String getWindowName()
		{
			return m_strWindow;
		}
        public void setWindowName(String value)
        {
            assert value != null; if(value == null) throw new IllegalArgumentException("value");
            m_strWindow = value;
        }

		private String m_strSequence = "";
		public String getSequence()
		{
			return m_strSequence;
		}
        public void setSequence(String value)
        {
            assert value != null; if(value == null) throw new IllegalArgumentException("value");
            m_strSequence = value;
        }

		public AutoTypeAssociation() { }

		public AutoTypeAssociation(String strWindow, String strSeq)
		{
			if(strWindow == null) throw new IllegalArgumentException("strWindow");
			if(strSeq == null) throw new IllegalArgumentException("strSeq");

			m_strWindow = strWindow;
			m_strSequence = strSeq;
		}

		public boolean Equals(AutoTypeAssociation other)
		{
			if(other == null) return false;

			if(m_strWindow != other.m_strWindow) return false;
			if(m_strSequence != other.m_strSequence) return false;

			return true;
		}

		public AutoTypeAssociation CloneDeep()
		{
			return new AutoTypeAssociation(m_strWindow, m_strSequence);
		}
	}

	/// <summary>
	/// A list of auto-type associations.
	/// </summary>
	public class AutoTypeConfig implements
		IDeepCloneable<AutoTypeConfig>
	{
		private boolean m_bEnabled = true;
		private AutoTypeObfuscationOptions m_atooObfuscation =
			AutoTypeObfuscationOptions.None;
		private String m_strDefaultSequence = "";
		private List<AutoTypeAssociation> m_lWindowAssocs =
			new ArrayList<AutoTypeAssociation>();

		/// <summary>
		/// Specify whether auto-type is enabled or not.
		/// </summary>
		public boolean isEnabled()
		{
			return m_bEnabled;
		}
        public void setEnabled(boolean value) { m_bEnabled = value; }

		/// <summary>
		/// Specify whether the typing should be obfuscated.
		/// </summary>
		public AutoTypeObfuscationOptions getObfuscationOptions()
		{
			return m_atooObfuscation;
		}
        public void setObfuscationOptions(AutoTypeObfuscationOptions value) { m_atooObfuscation = value; }

		/// <summary>
		/// The default keystroke sequence that is auto-typed if
		/// no matching window is found in the <c>Associations</c>
		/// container.
		/// </summary>
		public String getDefaultSequence()
		{
			return m_strDefaultSequence;
		}
        public void setDefaultSequence(String value)
        {
            assert value != null; if(value == null) throw new IllegalArgumentException("value");
            m_strDefaultSequence = value;
        }

		/// <summary>
		/// Get all auto-type window/keystroke sequence pairs.
		/// </summary>
		public Iterable<AutoTypeAssociation> getAssociations()
		{
			return m_lWindowAssocs;
		}

		public int getAssociationsCount()
		{
			return m_lWindowAssocs.size();
		}

		/// <summary>
		/// Construct a new auto-type associations list.
		/// </summary>
		public AutoTypeConfig()
		{
		}

		/// <summary>
		/// Remove all associations.
		/// </summary>
		public void Clear()
		{
			m_lWindowAssocs.clear();
		}

		/// <summary>
		/// Clone the auto-type associations list.
		/// </summary>
		/// <returns>New, cloned object.</returns>
		public AutoTypeConfig CloneDeep()
		{
			AutoTypeConfig newCfg = new AutoTypeConfig();

			newCfg.m_bEnabled = m_bEnabled;
			newCfg.m_atooObfuscation = m_atooObfuscation;
			newCfg.m_strDefaultSequence = m_strDefaultSequence;

			for(AutoTypeAssociation a : m_lWindowAssocs)
				newCfg.Add(a.CloneDeep());

			return newCfg;
		}

		public boolean Equals(AutoTypeConfig other)
		{
			if(other == null) { assert false; return false; }

			if(m_bEnabled != other.m_bEnabled) return false;
			if(m_atooObfuscation != other.m_atooObfuscation) return false;
			if(m_strDefaultSequence != other.m_strDefaultSequence) return false;

			if(m_lWindowAssocs.size() != other.m_lWindowAssocs.size()) return false;
			for(int i = 0; i < m_lWindowAssocs.size(); ++i)
			{
				if(!m_lWindowAssocs.get(i).Equals(other.m_lWindowAssocs.get(i)))
					return false;
			}

			return true;
		}

		public AutoTypeAssociation GetAt(int iIndex)
		{
			if((iIndex < 0) || (iIndex >= m_lWindowAssocs.size()))
				throw new ArrayIndexOutOfBoundsException("iIndex");

			return m_lWindowAssocs.get(iIndex);
		}

		public void Add(AutoTypeAssociation a)
		{
			if(a == null) { assert false; throw new IllegalArgumentException("a"); }

			m_lWindowAssocs.add(a);
		}

		public void Insert(int iIndex, AutoTypeAssociation a)
		{
			if((iIndex < 0) || (iIndex > m_lWindowAssocs.size()))
				throw new ArrayIndexOutOfBoundsException("iIndex");
			if(a == null) { assert false; throw new IllegalArgumentException("a"); }

			m_lWindowAssocs.add(iIndex, a);
		}

		public void RemoveAt(int iIndex)
		{
			if((iIndex < 0) || (iIndex >= m_lWindowAssocs.size()))
				throw new ArrayIndexOutOfBoundsException("iIndex");

			m_lWindowAssocs.remove(iIndex);
		}

		// public void Sort()
		// {
		//	m_lWindowAssocs.Sort(AutoTypeConfig.AssocCompareFn);
		// }

		// private static int AssocCompareFn(AutoTypeAssociation x,
		//	AutoTypeAssociation y)
		// {
		//	if(x == null) { assert false); return ((y == null) ? 0 : -1; }
		//	if(y == null) { assert false; return 1; }
		//	int cn = x.WindowName.CompareTo(y.WindowName);
		//	if(cn != 0) return cn;
		//	return x.Sequence.CompareTo(y.Sequence);
		// }
	}
