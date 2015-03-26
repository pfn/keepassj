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

import java.util.Map;
import java.util.TreeMap;
	public class PwObjectPool
	{
		private TreeMap<PwUuid, IStructureItem> m_dict =
			new TreeMap<PwUuid, IStructureItem>();

		public static PwObjectPool FromGroupRecursive(PwGroup pgRoot, boolean bEntries)
		{
			if(pgRoot == null) throw new IllegalArgumentException("pgRoot");

			final PwObjectPool p = new PwObjectPool();

			if(!bEntries) p.m_dict.put(pgRoot.getUuid(), pgRoot);
			GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
			{
				p.m_dict.put(pg.getUuid(), pg);
				return true;
			}};

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				p.m_dict.put(pe.getUuid(), pe);
				return true;
			}};

			pgRoot.TraverseTree(TraversalMethod.PreOrder, bEntries ? null : gh,
				bEntries ? eh : null);
			return p;
		}

		public IStructureItem Get(PwUuid pwUuid)
		{
            return m_dict.get(pwUuid);
		}

		public boolean ContainsOnlyType(Class<?> t)
		{
			for(Map.Entry<PwUuid, IStructureItem> kvp : m_dict.entrySet())
			{
				if(kvp.getValue().getClass() != t) return false;
			}

			return true;
		}
	}
