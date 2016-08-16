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
	static class PwObjectPoolEx
	{
		private Map<PwUuid, Long> m_dUuidToId =
			new HashMap<PwUuid, Long>();
		private HashMap<Long, IStructureItem> m_dIdToItem =
			new HashMap<Long, IStructureItem>();

		private PwObjectPoolEx()
		{
		}

		public static PwObjectPoolEx FromGroup(PwGroup pg)
		{
			PwObjectPoolEx p = new PwObjectPoolEx();

			if(pg == null) { assert(false); return p; }

			long[] uFreeId = { 2 }; // 0 = "not found", 1 is a hole

			p.m_dUuidToId.put(pg.getUuid(), uFreeId[0]);
			p.m_dIdToItem.put(uFreeId[0], pg);
			uFreeId[0] += 2; // Make hole

			p.AddGroupRec(pg, uFreeId);
			return p;
		}

		private void AddGroupRec(PwGroup pg, long[] uFreeId)
		{
			if(pg == null) { assert(false); return; }

			long[] uId = { uFreeId[0] };

			// Consecutive entries must have consecutive IDs
			for (PwEntry pe : pg.getEntries())
			{
				assert(!m_dUuidToId.containsKey(pe.getUuid()));
				assert(!m_dIdToItem.containsValue(pe));

				m_dUuidToId.put(pe.getUuid(), uId[0]);
				m_dIdToItem.put(uId[0], pe);
				++uId[0];
			}
			++uId[0]; // Make hole

			// Consecutive groups must have consecutive IDs
			for(PwGroup pgSub : pg.getGroups())
			{
				assert(!m_dUuidToId.containsKey(pgSub.getUuid()));
				assert(!m_dIdToItem.containsValue(pgSub));

				m_dUuidToId.put(pgSub.getUuid(), uId[0]);
				m_dIdToItem.put(uId[0], pgSub);
				++uId[0];
			}
			++uId[0]; // Make hole

			for(PwGroup pgSub : pg.getGroups())
			{
				AddGroupRec(pgSub, uId);
			}

			uFreeId[0] = uId[0];
		}

		public long GetIdByUuid(PwUuid pwUuid)
		{
			if(pwUuid == null) { assert(false); return 0; }

			Long uId;
			uId = m_dUuidToId.get(pwUuid);
			return uId == null ? 0 : uId;
		}

		public IStructureItem GetItemByUuid(PwUuid pwUuid)
		{
			if(pwUuid == null) { assert(false); return null; }

			Long uId;
			if((uId = m_dUuidToId.get(pwUuid)) == null) return null;
			assert(uId != 0);

			return GetItemById(uId);
		}

		public IStructureItem GetItemById(long uId)
		{
			IStructureItem p;
			p = m_dIdToItem.get(uId);
			return p;
		}
	}

	static class PwObjectBlock<T> implements Iterable<T>
//		where T : class, ITimeLogger, IStructureItem, IDeepCloneable<T>
	{
		private List<T> m_l = new ArrayList<T>();

		public T getPrimaryItem()
		{
			return ((m_l.size() > 0) ? m_l.get(0) : null);
		}

		private Date m_dtLocationChanged = new Date(0);
		public Date getLocationChanged()
		{
			return m_dtLocationChanged;
		}

		private PwObjectPoolEx m_poolAssoc = null;
		public PwObjectPoolEx getPoolAssoc()
		{
			return m_poolAssoc;
		}

		public PwObjectBlock()
		{
		}

		@Override public String toString()
		{
			return ("PwObjectBlock, Count = " + m_l.size());
		}

		public Iterator<T> iterator()
		{
			return m_l.iterator();
		}

		public void Add(T t, Date dtLoc, PwObjectPoolEx pool)
		{
			if(t == null) { assert(false); return; }

			m_l.add(t);

			if(dtLoc.getTime() > m_dtLocationChanged.getTime())
			{
				m_dtLocationChanged = dtLoc;
				m_poolAssoc = pool;
			}
		}
	}
}
