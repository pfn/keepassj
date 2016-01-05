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
import com.google.common.base.Joiner;
import com.google.common.base.Objects;
import com.google.common.base.Strings;

import java.util.*;
import java.util.regex.Pattern;

/// <summary>
	/// A group containing several password entries.
	/// </summary>
	public class PwGroup implements ITimeLogger, IStructureItem, IDeepCloneable<PwGroup>
	{
		public static final boolean DefaultAutoTypeEnabled = true;
		public static final boolean DefaultSearchingEnabled = true;

		private PwObjectList<PwGroup> m_listGroups = new PwObjectList<PwGroup>();
		private PwObjectList<PwEntry> m_listEntries = new PwObjectList<PwEntry>();
		private PwGroup m_pParentGroup = null;
		private Date m_tParentGroupLastMod = PwDefs.DtDefaultNow;

		private PwUuid m_uuid = PwUuid.Zero;
		private String m_strName = "";
		private String m_strNotes = "";

		private PwIcon m_pwIcon = PwIcon.Folder;
		private PwUuid m_pwCustomIconID = PwUuid.Zero;

		private Date m_tCreation = PwDefs.DtDefaultNow;
		private Date m_tLastMod = PwDefs.DtDefaultNow;
		private Date m_tLastAccess = PwDefs.DtDefaultNow;
		private Date m_tExpire = PwDefs.DtDefaultNow;
		private boolean m_bExpires = false;
		private long m_uUsageCount = 0;

		private boolean m_bIsExpanded = true;
		private boolean m_bVirtual = false;

		private String m_strDefaultAutoTypeSequence = "";

		private Boolean m_bEnableAutoType = null;
		private Boolean m_bEnableSearching = null;

		private PwUuid m_pwLastTopVisibleEntry = PwUuid.Zero;

		/// <summary>
		/// UUID of this group.
		/// </summary>
		public PwUuid getUuid()
		{
			return m_uuid;
		}
			public void setUuid(PwUuid value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_uuid = value;
			}

		/// <summary>
		/// The name of this group. Cannot be <c>null</c>.
		/// </summary>
		public String getName()
		{
			return m_strName;
		}
			public void setName(String value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_strName = value;
			}

		/// <summary>
		/// Comments about this group. Cannot be <c>null</c>.
		/// </summary>
		public String getNotes()
		{
			return m_strNotes;
		}
			public void setNotes(String value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_strNotes = value;
			}

		/// <summary>
		/// Icon of the group.
		/// </summary>
		public PwIcon getIconId()
		{
			return m_pwIcon;
		}
			public void setIconId(PwIcon value) { m_pwIcon = value; }

		/// <summary>
		/// Get the custom icon ID. This value is 0, if no custom icon is
		/// being used (i.e. the icon specified by the <c>IconID</c> property
		/// should be displayed).
		/// </summary>
		public PwUuid getCustomIconUuid()
		{
			return m_pwCustomIconID;
		}
			public void setCustomIconUuid(PwUuid value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_pwCustomIconID = value;
			}

		/// <summary>
		/// Reference to the group to which this group belongs. May be <c>null</c>.
		/// </summary>
		public PwGroup getParentGroup()
		{
			return m_pParentGroup;

		}
			// Plugins: use <c>PwGroup.AddGroup</c> instead.
			public void setParentGroup(PwGroup value) { assert value != this; m_pParentGroup = value; }

		/// <summary>
		/// The date/time when the location of the object was last changed.
		/// </summary>
		public Date getLocationChanged()
		{
			return m_tParentGroupLastMod;
		}
			public void setLocationChanged(Date value) { m_tParentGroupLastMod = value; }

		/// <summary>
		/// A flag that specifies if the group is shown as expanded or
		/// collapsed in the user interface.
		/// </summary>
		public boolean isExpanded()
		{
			return m_bIsExpanded;
		}
			public void setExpanded(boolean value) { m_bIsExpanded = value; }

		/// <summary>
		/// The date/time when this group was created.
		/// </summary>
		public Date getCreationTime()
		{
			return m_tCreation;
		}
			public void setCreationTime(Date value) { m_tCreation = value; }

		/// <summary>
		/// The date/time when this group was last modified.
		/// </summary>
		public Date getLastModificationTime()
		{
			return m_tLastMod;
		}
			public void setLastModificationTime(Date value) { m_tLastMod = value; }

		/// <summary>
		/// The date/time when this group was last accessed (read).
		/// </summary>
		public Date getLastAccessTime()
		{
			return m_tLastAccess;
		}
			public void setLastAccessTime(Date value) { m_tLastAccess = value; }

		/// <summary>
		/// The date/time when this group expires.
		/// </summary>
		public Date getExpiryTime()
		{
			return m_tExpire;
		}
			public void setExpiryTime(Date value) { m_tExpire = value; }

		/// <summary>
		/// Flag that determines if the group expires.
		/// </summary>
		public boolean getExpires()
		{
			return m_bExpires;
		}
			public void setExpires(boolean value) { m_bExpires = value; }

		/// <summary>
		/// Get or set the usage count of the group. To increase the usage
		/// count by one, use the <c>Touch</c> function.
		/// </summary>
		public long getUsageCount()
		{
			return m_uUsageCount;
		}
			public void setUsageCount(long value) { m_uUsageCount = value; }

		/// <summary>
		/// Get a list of subgroups in this group.
		/// </summary>
		public PwObjectList<PwGroup> getGroups()
		{
			return m_listGroups;
		}

		/// <summary>
		/// Get a list of entries in this group.
		/// </summary>
		public PwObjectList<PwEntry> getEntries()
		{
			return m_listEntries;
		}

		/// <summary>
		/// A flag specifying whether this group is virtual or not. Virtual
		/// groups can contain links to entries stored in other groups.
		/// Note that this flag has to be interpreted and set by the calling
		/// code; it won't prevent you from accessing and modifying the list
		/// of entries in this group in any way.
		/// </summary>
		public boolean isVirtual()
		{
			return m_bVirtual;
		}
			public void setVirtual(boolean value) { m_bVirtual = value; }

		/// <summary>
		/// Default auto-type keystroke sequence for all entries in
		/// this group. This property can be an empty String, which
		/// means that the value should be inherited from the parent.
		/// </summary>
		public String getDefaultAutoTypeSequence()
		{
			return m_strDefaultAutoTypeSequence;
		}
			public void setDefaultAutoTypeSequence(String value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_strDefaultAutoTypeSequence = value;
			}

		public Boolean getEnableAutoType()
		{
			return m_bEnableAutoType;
		}
			public void setEnableAutoType(Boolean value) { m_bEnableAutoType = value; }

		public Boolean getEnableSearching()
		{
			return m_bEnableSearching;
		}
        public void setEnableSearching(Boolean value) {
            m_bEnableSearching = value;
        }

		public PwUuid getLastTopVisibleEntry()
		{
			return m_pwLastTopVisibleEntry;
		}
			public void setLastTopVisibleEntry(PwUuid value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_pwLastTopVisibleEntry = value;
			}

		public static List<EventHandler<ObjectTouchedEventArgs>> GroupTouched = new ArrayList<>();
		public List<EventHandler<ObjectTouchedEventArgs>> Touched = new ArrayList<>();

		/// <summary>
		/// Construct a new, empty group.
		/// </summary>
		public PwGroup()
		{
		}

		/// <summary>
		/// Construct a new, empty group.
		/// </summary>
		/// <param name="bCreateNewUuid">Create a new UUID for this group.</param>
		/// <param name="bSetTimes">Set creation, last access and last modification times to the current time.</param>
		public PwGroup(boolean bCreateNewUuid, boolean bSetTimes)
		{
			if(bCreateNewUuid) m_uuid = new PwUuid(true);

			if(bSetTimes)
			{
				m_tCreation = m_tLastMod = m_tLastAccess =
					m_tParentGroupLastMod = new Date();
			}
		}

		/// <summary>
		/// Construct a new group.
		/// </summary>
		/// <param name="bCreateNewUuid">Create a new UUID for this group.</param>
		/// <param name="bSetTimes">Set creation, last access and last modification times to the current time.</param>
		/// <param name="strName">Name of the new group.</param>
		/// <param name="pwIcon">Icon of the new group.</param>
		public PwGroup(boolean bCreateNewUuid, boolean bSetTimes, String strName, PwIcon pwIcon)
		{
			if(bCreateNewUuid) m_uuid = new PwUuid(true);

			if(bSetTimes)
			{
				m_tCreation = m_tLastMod = m_tLastAccess =
					m_tParentGroupLastMod = new Date();
			}

			if(strName != null) m_strName = strName;

			m_pwIcon = pwIcon;
		}

		/// <summary>
		/// Deeply clone the current group. The returned group will be an exact
		/// value copy of the current object (including UUID, etc.).
		/// </summary>
		/// <returns>Exact value copy of the current <c>PwGroup</c> object.</returns>
		public PwGroup CloneDeep()
		{
			PwGroup pg = new PwGroup(false, false);

			pg.m_uuid = m_uuid; // PwUuid is immutable

			pg.m_listGroups = m_listGroups.CloneDeep();
			pg.m_listEntries = m_listEntries.CloneDeep();
			pg.m_pParentGroup = m_pParentGroup;
			pg.m_tParentGroupLastMod = m_tParentGroupLastMod;

			pg.m_strName = m_strName;
			pg.m_strNotes = m_strNotes;

			pg.m_pwIcon = m_pwIcon;
			pg.m_pwCustomIconID = m_pwCustomIconID;

			pg.m_tCreation = m_tCreation;
			pg.m_tLastMod = m_tLastMod;
			pg.m_tLastAccess = m_tLastAccess;
			pg.m_tExpire = m_tExpire;
			pg.m_bExpires = m_bExpires;
			pg.m_uUsageCount = m_uUsageCount;

			pg.m_bIsExpanded = m_bIsExpanded;
			pg.m_bVirtual = m_bVirtual;

			pg.m_strDefaultAutoTypeSequence = m_strDefaultAutoTypeSequence;

			pg.m_bEnableAutoType = m_bEnableAutoType;
			pg.m_bEnableSearching = m_bEnableSearching;

			pg.m_pwLastTopVisibleEntry = m_pwLastTopVisibleEntry;

			return pg;
		}

		public PwGroup CloneStructure()
		{
			PwGroup pg = new PwGroup(false, false);

			pg.m_uuid = m_uuid; // PwUuid is immutable
			pg.m_tParentGroupLastMod = m_tParentGroupLastMod;
			// Do not assign m_pParentGroup

			for (PwGroup pgSub : m_listGroups)
				pg.AddGroup(pgSub.CloneStructure(), true);

			for(PwEntry peSub : m_listEntries)
				pg.AddEntry(peSub.CloneStructure(), true);

			return pg;
		}

		public boolean EqualsGroup(PwGroup pg, PwCompareOptions.Options pwOpt,
			MemProtCmpMode mpCmpStr)
		{
			if(pg == null) { assert false; return false; }

			boolean bIgnoreLastAccess = pwOpt.contains(PwCompareOptions.IgnoreLastAccess);
			boolean bIgnoreLastMod = pwOpt.contains(PwCompareOptions.IgnoreLastMod);

			if(!m_uuid.Equals(pg.m_uuid)) return false;
			if(!pwOpt.contains(PwCompareOptions.IgnoreParentGroup))
			{
				if(m_pParentGroup != pg.m_pParentGroup) return false;
				if(!bIgnoreLastMod && (!Objects.equal(m_tParentGroupLastMod, pg.m_tParentGroupLastMod)))
					return false;
			}

			if(!Objects.equal(m_strName, pg.m_strName)) return false;
			if(!Objects.equal(m_strNotes, pg.m_strNotes)) return false;

			if(m_pwIcon != pg.m_pwIcon) return false;
			if(!m_pwCustomIconID.Equals(pg.m_pwCustomIconID)) return false;

			if(!Objects.equal(m_tCreation, pg.m_tCreation)) return false;
			if(!bIgnoreLastMod && (!Objects.equal(m_tLastMod, pg.m_tLastMod))) return false;
			if(!bIgnoreLastAccess && (!Objects.equal(m_tLastAccess, pg.m_tLastAccess))) return false;
			if(!Objects.equal(m_tExpire, pg.m_tExpire)) return false;
			if(m_bExpires != pg.m_bExpires) return false;
			if(!bIgnoreLastAccess && (m_uUsageCount != pg.m_uUsageCount)) return false;

			// if(m_bIsExpanded != pg.m_bIsExpanded) return false;

			if(!m_strDefaultAutoTypeSequence.equals(pg.m_strDefaultAutoTypeSequence)) return false;

            if(m_bEnableAutoType != pg.m_bEnableAutoType) return false;
            if(m_bEnableSearching != pg.m_bEnableSearching) return false;

			if(!m_pwLastTopVisibleEntry.Equals(pg.m_pwLastTopVisibleEntry)) return false;

			if(!pwOpt.contains(PwCompareOptions.PropertiesOnly))
			{
				if(m_listEntries.getUCount() != pg.m_listEntries.getUCount()) return false;
				for(int u = 0; u < m_listEntries.getUCount(); ++u)
				{
					PwEntry peA = m_listEntries.GetAt(u);
					PwEntry peB = pg.m_listEntries.GetAt(u);
					if(!peA.EqualsEntry(peB, pwOpt, mpCmpStr)) return false;
				}

				if(m_listGroups.getUCount() != pg.m_listGroups.getUCount()) return false;
				for(int u = 0; u < m_listGroups.getUCount(); ++u)
				{
					PwGroup pgA = m_listGroups.GetAt(u);
					PwGroup pgB = pg.m_listGroups.GetAt(u);
					if(!pgA.EqualsGroup(pgB, pwOpt, mpCmpStr)) return false;
				}
			}

			return true;
		}

		/// <summary>
		/// Assign properties to the current group based on a template group.
		/// </summary>
		/// <param name="pgTemplate">Template group. Must not be <c>null</c>.</param>
		/// <param name="bOnlyIfNewer">Only set the properties of the template group
		/// if it is newer than the current one.</param>
		/// <param name="bAssignLocationChanged">If <c>true</c>, the
		/// <c>LocationChanged</c> property is copied, otherwise not.</param>
		public void AssignProperties(PwGroup pgTemplate, boolean bOnlyIfNewer,
			boolean bAssignLocationChanged)
		{
			assert pgTemplate != null; if(pgTemplate == null) throw new IllegalArgumentException("pgTemplate");

			if(bOnlyIfNewer && (TimeUtil.Compare(pgTemplate.m_tLastMod, m_tLastMod,
				true) < 0))
				return;

			// Template UUID should be the same as the current one
			assert m_uuid.Equals(pgTemplate.m_uuid);
			m_uuid = pgTemplate.m_uuid;

			if(bAssignLocationChanged)
				m_tParentGroupLastMod = pgTemplate.m_tParentGroupLastMod;

			m_strName = pgTemplate.m_strName;
			m_strNotes = pgTemplate.m_strNotes;

			m_pwIcon = pgTemplate.m_pwIcon;
			m_pwCustomIconID = pgTemplate.m_pwCustomIconID;

			m_tCreation = pgTemplate.m_tCreation;
			m_tLastMod = pgTemplate.m_tLastMod;
			m_tLastAccess = pgTemplate.m_tLastAccess;
			m_tExpire = pgTemplate.m_tExpire;
			m_bExpires = pgTemplate.m_bExpires;
			m_uUsageCount = pgTemplate.m_uUsageCount;

			m_strDefaultAutoTypeSequence = pgTemplate.m_strDefaultAutoTypeSequence;

			m_bEnableAutoType = pgTemplate.m_bEnableAutoType;
			m_bEnableSearching = pgTemplate.m_bEnableSearching;

			m_pwLastTopVisibleEntry = pgTemplate.m_pwLastTopVisibleEntry;
		}

		/// <summary>
		/// Touch the group. This function updates the internal last access
		/// time. If the <paramref name="bModified" /> parameter is <c>true</c>,
		/// the last modification time gets updated, too.
		/// </summary>
		/// <param name="bModified">Modify last modification time.</param>
		public void Touch(boolean bModified)
		{
			Touch(bModified, true);
		}

		/// <summary>
		/// Touch the group. This function updates the internal last access
		/// time. If the <paramref name="bModified" /> parameter is <c>true</c>,
		/// the last modification time gets updated, too.
		/// </summary>
		/// <param name="bModified">Modify last modification time.</param>
		/// <param name="bTouchParents">If <c>true</c>, all parent objects
		/// get touched, too.</param>
		public void Touch(boolean bModified, boolean bTouchParents)
		{
			m_tLastAccess = new Date();
			++m_uUsageCount;

			if(bModified) m_tLastMod = m_tLastAccess;

			for (EventHandler<ObjectTouchedEventArgs> h : this.Touched)
				h.delegate(this, new ObjectTouchedEventArgs(this,
					bModified, bTouchParents));
			for (EventHandler<ObjectTouchedEventArgs> h : PwGroup.GroupTouched)
				h.delegate(this, new ObjectTouchedEventArgs(this,
					bModified, bTouchParents));

			if(bTouchParents && (m_pParentGroup != null))
				m_pParentGroup.Touch(bModified, true);
		}

		/// <summary>
		/// Get number of groups and entries in the current group. This function
		/// can also traverse through all subgroups and accumulate their counts
		/// (recursive mode).
		/// </summary>
		/// <param name="bRecursive">If this parameter is <c>true</c>, all
		/// subgroups and entries in subgroups will be counted and added to
		/// the returned value. If it is <c>false</c>, only the number of
		/// subgroups and entries of the current group is returned.</param>
		/// <param name="uNumGroups">Number of subgroups.</param>
		/// <param name="uNumEntries">Number of entries.</param>
		public void GetCounts(boolean bRecursive, /* out */int[] uNumGroups, /* out */int[] uNumEntries)
		{
			if(bRecursive)
			{
				int uTotalGroups = m_listGroups.getUCount();
				int uTotalEntries = m_listEntries.getUCount();
				int[] uSubGroupCount = new int[1], uSubEntryCount = new int[1];

				for(PwGroup pg : m_listGroups)
				{
					pg.GetCounts(true, uSubGroupCount, uSubEntryCount);

					uTotalGroups += uSubGroupCount[0];
					uTotalEntries += uSubEntryCount[0];
				}

				uNumGroups[0] = uTotalGroups;
				uNumEntries[0] = uTotalEntries;
			}
			else // !bRecursive
			{
				uNumGroups[0] = m_listGroups.getUCount();
				uNumEntries[0] = m_listEntries.getUCount();
			}
		}

		public int GetEntriesCount(boolean bRecursive)
		{
			int[] uGroups = new int[1], uEntries = new int[1];
			GetCounts(bRecursive, uGroups, uEntries);
			return uEntries[0];
		}

		/// <summary>
		/// Traverse the group/entry tree in the current group. Various traversal
		/// methods are available.
		/// </summary>
		/// <param name="tm">Specifies the traversal method.</param>
		/// <param name="groupHandler">Function that performs an action on
		/// the currently visited group (see <c>GroupHandler</c> for more).
		/// This parameter may be <c>null</c>, in this case the tree is traversed but
		/// you don't get notifications for each visited group.</param>
		/// <param name="entryHandler">Function that performs an action on
		/// the currently visited entry (see <c>EntryHandler</c> for more).
		/// This parameter may be <c>null</c>.</param>
		/// <returns>Returns <c>true</c> if all entries and groups have been
		/// traversed. If the traversal has been canceled by one of the two
		/// handlers, the return value is <c>false</c>.</returns>
		public boolean TraverseTree(TraversalMethod tm, GroupHandler groupHandler, EntryHandler entryHandler)
		{
			boolean bRet = false;

			switch(tm)
			{
				case None:
					bRet = true;
					break;
				case PreOrder:
					bRet = PreOrderTraverseTree(groupHandler, entryHandler);
					break;
				default:
					assert false;
					break;
			}

			return bRet;
		}

		private boolean PreOrderTraverseTree(GroupHandler groupHandler, EntryHandler entryHandler)
		{
			if(entryHandler != null)
			{
				for(PwEntry pe : m_listEntries)
				{
					if(!entryHandler.delegate(pe)) return false;
				}
			}

			if(groupHandler != null)
			{
				for(PwGroup pg : m_listGroups)
				{
					if(!groupHandler.delegate(pg)) return false;

					pg.PreOrderTraverseTree(groupHandler, entryHandler);
				}
			}
			else // groupHandler == null
			{
				for(PwGroup pg : m_listGroups)
				{
					pg.PreOrderTraverseTree(null, entryHandler);
				}
			}

			return true;
		}

		/// <summary>
		/// Pack all groups into one flat linked list of references (recursively).
		/// </summary>
		/// <returns>Flat list of all groups.</returns>
		public LinkedList<PwGroup> GetFlatGroupList()
		{
			LinkedList<PwGroup> list = new LinkedList<PwGroup>();

			for(PwGroup pg : m_listGroups)
			{
				list.add(pg);

				if(pg.getGroups().getUCount() != 0)
					LinearizeGroupRecursive(list, pg, 1);
			}

			return list;
		}

		private void LinearizeGroupRecursive(LinkedList<PwGroup> list, PwGroup pg, int uLevel)
		{
			assert pg != null; if(pg == null) return;

			for(PwGroup pwg : pg.getGroups())
			{
				list.add(pwg);

				if(pwg.getGroups().getUCount() != 0)
					LinearizeGroupRecursive(list, pwg, (short)(uLevel + 1));
			}
		}

		/// <summary>
		/// Pack all entries into one flat linked list of references. Temporary
		/// group IDs are assigned automatically.
		/// </summary>
		/// <param name="flatGroupList">A flat group list created by
		/// <c>GetFlatGroupList</c>.</param>
		/// <returns>Flat list of all entries.</returns>
		public static LinkedList<PwEntry> GetFlatEntryList(LinkedList<PwGroup> flatGroupList)
		{
			assert flatGroupList != null; if(flatGroupList == null) return null;

			LinkedList<PwEntry> list = new LinkedList<PwEntry>();
			for(PwGroup pg : flatGroupList)
			{
				for(PwEntry pe : pg.getEntries())
					list.add(pe);
			}

			return list;
		}

		/// <summary>
		/// Enable protection of a specific String field type.
		/// </summary>
		/// <param name="strFieldName">Name of the String field to protect or unprotect.</param>
		/// <param name="bEnable">Enable protection or not.</param>
		/// <returns>Returns <c>true</c>, if the operation completed successfully,
		/// otherwise <c>false</c>.</returns>
		public boolean EnableStringFieldProtection(final String strFieldName, final boolean bEnable)
		{
			assert strFieldName != null;

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				// Enable protection of current String
				pe.getStrings().EnableProtection(strFieldName, bEnable);

				// Do the same for all history items
				for(PwEntry peHistory : pe.getHistory())
				{
					peHistory.getStrings().EnableProtection(strFieldName, bEnable);
				}

				return true;
			}};

			return PreOrderTraverseTree(null, eh);
		}

		/// <summary>
		/// Search this group and all subgroups for entries.
		/// </summary>
		/// <param name="sp">Specifies the search method.</param>
		/// <param name="listStorage">Entry list in which the search results will
		/// be stored.</param>
		public void SearchEntries(SearchParameters sp, PwObjectList<PwEntry> listStorage)
		{
			SearchEntries(sp, listStorage, null);
		}

		/// <summary>
		/// Search this group and all subgroups for entries.
		/// </summary>
		/// <param name="sp">Specifies the search method.</param>
		/// <param name="listStorage">Entry list in which the search results will
		/// be stored.</param>
		/// <param name="slStatus">Optional status reporting object.</param>
		public void SearchEntries(SearchParameters sp, PwObjectList<PwEntry> listStorage,
			IStatusLogger slStatus)
		{
			if(sp == null) { assert false; return; }
			if(listStorage == null) { assert false; return; }

			long[] uCurEntries = new long[1];
            long uTotalEntries = 0;

			List<String> lTerms = StrUtil.SplitSearchTerms(sp.getSearchString());
			if((lTerms.size() <= 1) || sp.getRegularExpression())
			{
				if(slStatus != null) uTotalEntries = GetEntriesCount(true);
				SearchEntriesSingle(sp, listStorage, slStatus, uCurEntries,
					uTotalEntries);
				return;
			}

			// Search longer strings first (for improved performance)
			Collections.sort(lTerms, StrUtil.CompareLengthGt);

			String strFullSearch = sp.getSearchString(); // Backup

			PwGroup pg = this;
			for(int iTerm = 0; iTerm < lTerms.size(); ++iTerm)
			{
				// Update counters for a better state guess
				if(slStatus != null)
				{
					long uRemRounds = (long)(lTerms.size() - iTerm);
					uTotalEntries = uCurEntries[0] + (uRemRounds *
						pg.GetEntriesCount(true));
				}

				PwGroup pgNew = new PwGroup();

				sp.setSearchString(lTerms.get(iTerm));

				boolean bNegate = false;
				if(sp.getSearchString().startsWith("-"))
				{
					sp.setSearchString(sp.getSearchString().substring(1));
					bNegate = (sp.getSearchString().length() > 0);
				}

				if(!pg.SearchEntriesSingle(sp, pgNew.getEntries(), slStatus,
					uCurEntries, uTotalEntries))
				{
					pg = null;
					break;
				}

				if(bNegate)
				{
					PwObjectList<PwEntry> lCand = pg.GetEntries(true);

					pg = new PwGroup();
					for(PwEntry peCand : lCand)
					{
						if(pgNew.getEntries().IndexOf(peCand) < 0) pg.getEntries().Add(peCand);
					}
				}
				else pg = pgNew;
			}

			if(pg != null) listStorage.Add(pg.getEntries());
			sp.setSearchString(strFullSearch); // Restore
		}

		private boolean SearchEntriesSingle(SearchParameters spIn,
			final PwObjectList<PwEntry> listStorage, final IStatusLogger slStatus,
			long[] uCurEntries, final long uTotalEntries)
		{
			final SearchParameters sp = spIn.Clone();
			if(sp.getSearchString() == null) { assert false; return true; }
			sp.setSearchString(sp.getSearchString().trim());

			final boolean bTitle = sp.getSearchInTitles();
			final boolean bUserName = sp.getSearchInUserNames();
			final boolean bPassword = sp.getSearchInPasswords();
			final boolean bUrl = sp.getSearchInUrls();
			final boolean bNotes = sp.getSearchInNotes();
			final boolean bOther = sp.getSearchInOther();
			final boolean bUuids = sp.getSearchInUuids();
			final boolean bGroupName = sp.getSearchInGroupNames();
			final boolean bTags = sp.getSearchInTags();
			final boolean bExcludeExpired = sp.getExcludeExpired();
			final boolean bRespectEntrySearchingDisabled = sp.getRespectEntrySearchingDisabled();

			final Date dtNow = new Date();

			Pattern _rx = null;
			if(sp.getRegularExpression())
			{
                int ro = 0;
				if((sp.getComparisonMode() == StringComparison.CurrentCultureIgnoreCase) ||
					(sp.getComparisonMode() == StringComparison.InvariantCultureIgnoreCase) ||
					(sp.getComparisonMode() == StringComparison.OrdinalIgnoreCase))
				{
					ro |= Pattern.CASE_INSENSITIVE;
				}

				_rx = Pattern.compile(sp.getSearchString(), ro);
			}
            final Pattern rx = _rx;

			final long[] uLocalCurEntries = uCurEntries;

			EntryHandler eh = null;
			if(sp.getSearchString().length() <= 0) // Report all
			{
				eh = new EntryHandler() { public boolean delegate(PwEntry pe)
				{
					if(slStatus != null)
					{
						if(!slStatus.SetProgress((int)((uLocalCurEntries[0] *
							100L) / uTotalEntries))) return false;
						++uLocalCurEntries[0];
					}

					if(bRespectEntrySearchingDisabled && !pe.GetSearchingEnabled())
						return true; // Skip
					if(bExcludeExpired && pe.getExpires() && (dtNow.getTime() > pe.getExpiryTime().getTime()))
						return true; // Skip

					listStorage.Add(pe);
					return true;
				}};
			}
			else
			{
				eh = new EntryHandler() { public boolean delegate(PwEntry pe)
				{
					if(slStatus != null)
					{
						if(!slStatus.SetProgress((int)((uLocalCurEntries[0] *
							100L) / uTotalEntries))) return false;
						++uLocalCurEntries[0];
					}

					if(bRespectEntrySearchingDisabled && !pe.GetSearchingEnabled())
						return true; // Skip
					if(bExcludeExpired && pe.getExpires() && (dtNow.getTime() > pe.getExpiryTime().getTime()))
						return true; // Skip

					int uInitialResults = listStorage.getUCount();

					for(Map.Entry<String, ProtectedString> kvp : pe.getStrings())
					{
						String strKey = kvp.getKey();

						if(strKey.equals(PwDefs.TitleField))
						{
							if(bTitle) SearchEvalAdd(sp, kvp.getValue().ReadString(),
								rx, pe, listStorage);
						}
						else if(strKey.equals(PwDefs.UserNameField))
						{
							if(bUserName) SearchEvalAdd(sp, kvp.getValue().ReadString(),
								rx, pe, listStorage);
						}
						else if(strKey.equals(PwDefs.PasswordField))
						{
							if(bPassword) SearchEvalAdd(sp, kvp.getValue().ReadString(),
								rx, pe, listStorage);
						}
						else if(strKey.equals(PwDefs.UrlField))
						{
							if(bUrl) SearchEvalAdd(sp, kvp.getValue().ReadString(),
								rx, pe, listStorage);
						}
						else if(strKey.equals(PwDefs.NotesField))
						{
							if(bNotes) SearchEvalAdd(sp, kvp.getValue().ReadString(),
								rx, pe, listStorage);
						}
						else if(bOther)
							SearchEvalAdd(sp, kvp.getValue().ReadString(),
								rx, pe, listStorage);

						// An entry can match only once => break if we have added it
						if(listStorage.getUCount() > uInitialResults) break;
					}

					if(bUuids && (listStorage.getUCount() == uInitialResults))
						SearchEvalAdd(sp, pe.getUuid().ToHexString(), rx, pe, listStorage);

					if(bGroupName && (listStorage.getUCount() == uInitialResults) &&
						(pe.getParentGroup() != null))
						SearchEvalAdd(sp, pe.getParentGroup().getName(), rx, pe, listStorage);

					if(bTags)
					{
						for(String strTag : pe.getTags())
						{
							if(listStorage.getUCount() != uInitialResults) break; // Match

							SearchEvalAdd(sp, strTag, rx, pe, listStorage);
						}
					}

					return true;
                }};
			}

			if(!PreOrderTraverseTree(null, eh)) return false;
			uCurEntries = uLocalCurEntries;
			return true;
		}

		private static void SearchEvalAdd(SearchParameters sp, String strDataField,
			Pattern rx, PwEntry pe, PwObjectList<PwEntry> lResults)
		{
            StringComparison mode = sp.getComparisonMode();
            boolean ignoreCase =
                    mode == StringComparison.OrdinalIgnoreCase ||
                    mode == StringComparison.CurrentCultureIgnoreCase ||
                    mode == StringComparison.InvariantCultureIgnoreCase;
            boolean bMatch = false;

			if(rx == null)
				bMatch = (ignoreCase ? strDataField.toLowerCase() : strDataField).contains(ignoreCase ? sp.getSearchString().toLowerCase() : sp.getSearchString());
			else bMatch = rx.matcher(strDataField).matches();

			if(!bMatch && (sp.getDataTransformationFn() != null))
			{
				String strCmp = sp.getDataTransformationFn().delegate(strDataField, pe);
				if(!strCmp.equals(strDataField))
				{
					if(rx == null)
						bMatch = (ignoreCase ?
                                strCmp.toLowerCase() : strCmp).contains(
                                ignoreCase ?
                                        sp.getSearchString().toLowerCase() : sp.getSearchString());
					else bMatch = rx.matcher(strCmp).matches();
				}
			}

			if(bMatch) lResults.Add(pe);
		}

		public List<String> BuildEntryTagsList()
		{
			return BuildEntryTagsList(false);
		}

		public List<String> BuildEntryTagsList(boolean bSort)
		{
			final List<String> vTags = new ArrayList<String>();

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				for(String strTag : pe.getTags())
				{
					boolean bFound = false;
					for(int i = 0; i < vTags.size(); ++i)
					{
						if(vTags.get(i).equalsIgnoreCase(strTag))
						{
							bFound = true;
							break;
						}
					}

					if(!bFound) vTags.add(strTag);
				}

				return true;
            }};

			TraverseTree(TraversalMethod.PreOrder, null, eh);
			if(bSort) Collections.sort(vTags, StrUtil.CaseIgnoreComparer);
			return vTags;
		}

		public Map<String, Integer> BuildEntryTagsDict(boolean bSort)
		{
			final Map<String, Integer> d = new TreeMap<String, Integer>(StrUtil.CaseIgnoreComparer);

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				for(String strTag : pe.getTags())
				{
					if(d.containsKey(strTag)) d.put(strTag, d.get(strTag) + 1);
					else d.put(strTag, 1);
				}

				return true;
            }};

			TraverseTree(TraversalMethod.PreOrder, null, eh);
			return d;
		}

		public void FindEntriesByTag(String strTag, PwObjectList<PwEntry> listStorage,
			boolean bSearchRecursive)
		{
			if(strTag == null) throw new IllegalArgumentException("strTag");
			if(strTag.length() == 0) return;

			for(PwEntry pe : m_listEntries)
			{
				for(String strEntryTag : pe.getTags())
				{
					if(strEntryTag.equalsIgnoreCase(strTag))
					{
						listStorage.Add(pe);
						break;
					}
				}
			}

			if(bSearchRecursive)
			{
				for(PwGroup pg : m_listGroups)
					pg.FindEntriesByTag(strTag, listStorage, true);
			}
		}

		/// <summary>
		/// Find a group.
		/// </summary>
		/// <param name="uuid">UUID identifying the group the caller is looking for.</param>
		/// <param name="bSearchRecursive">If <c>true</c>, the search is recursive.</param>
		/// <returns>Returns reference to found group, otherwise <c>null</c>.</returns>
		public PwGroup FindGroup(PwUuid uuid, boolean bSearchRecursive)
		{
			// Do not assert on PwUuid.Zero
			if(m_uuid.Equals(uuid)) return this;

			if(bSearchRecursive)
			{
				PwGroup pgRec;
				for(PwGroup pg : m_listGroups)
				{
					pgRec = pg.FindGroup(uuid, true);
					if(pgRec != null) return pgRec;
				}
			}
			else // Not recursive
			{
				for(PwGroup pg : m_listGroups)
				{
					if(pg.m_uuid.Equals(uuid))
						return pg;
				}
			}

			return null;
		}

		/// <summary>
		/// Find an object.
		/// </summary>
		/// <param name="uuid">UUID of the object to find.</param>
		/// <param name="bRecursive">Specifies whether to search recursively.</param>
		/// <param name="bEntries">If <c>null</c>, groups and entries are
		/// searched. If <c>true</c>, only entries are searched. If <c>false</c>,
		/// only groups are searched.</param>
		/// <returns>Reference to the object, if found. Otherwise <c>null</c>.</returns>
		public IStructureItem FindObject(PwUuid uuid, boolean bRecursive,
			Boolean bEntries)
		{
			if(bEntries != null)
			{
				if(bEntries) return FindEntry(uuid, bRecursive);
				else return FindGroup(uuid, bRecursive);
			}

			PwGroup pg = FindGroup(uuid, bRecursive);
			if(pg != null) return pg;
			return FindEntry(uuid, bRecursive);
		}

		/// <summary>
		/// Try to find a subgroup and create it, if it doesn't exist yet.
		/// </summary>
		/// <param name="strName">Name of the subgroup.</param>
		/// <param name="bCreateIfNotFound">If the group isn't found: create it.</param>
		/// <returns>Returns a reference to the requested group or <c>null</c> if
		/// it doesn't exist and shouldn't be created.</returns>
		public PwGroup FindCreateGroup(String strName, boolean bCreateIfNotFound)
		{
			assert strName != null; if(strName == null) throw new IllegalArgumentException("strName");

			for(PwGroup pg : m_listGroups)
			{
				if(Objects.equal(pg.getName(), strName)) return pg;
			}

			if(!bCreateIfNotFound) return null;

			PwGroup pgNew = new PwGroup(true, true, strName, PwIcon.Folder);
			AddGroup(pgNew, true);
			return pgNew;
		}

		/// <summary>
		/// Find an entry.
		/// </summary>
		/// <param name="uuid">UUID identifying the entry the caller is looking for.</param>
		/// <param name="bSearchRecursive">If <c>true</c>, the search is recursive.</param>
		/// <returns>Returns reference to found entry, otherwise <c>null</c>.</returns>
		public PwEntry FindEntry(PwUuid uuid, boolean bSearchRecursive)
		{
			for(PwEntry pe : m_listEntries)
			{
				if(pe.getUuid().Equals(uuid)) return pe;
			}

			if(bSearchRecursive)
			{
				PwEntry peSub;
				for(PwGroup pg : m_listGroups)
				{
					peSub = pg.FindEntry(uuid, true);
					if(peSub != null) return peSub;
				}
			}

			return null;
		}

		/// <summary>
		/// Get the full path of a group.
		/// </summary>
		/// <returns>Full path of the group.</returns>
		public String GetFullPath()
		{
			return GetFullPath(".", false);
		}

		/// <summary>
		/// Get the full path of a group.
		/// </summary>
		/// <param name="strSeparator">String that separates the group
		/// names.</param>
		/// <param name="bIncludeTopMostGroup">Specifies whether the returned
		/// path starts with the topmost group.</param>
		/// <returns>Full path of the group.</returns>
		public String GetFullPath(String strSeparator, boolean bIncludeTopMostGroup)
		{
			assert strSeparator != null;
			if(strSeparator == null) throw new IllegalArgumentException("strSeparator");

			String strPath = m_strName;

			PwGroup pg = m_pParentGroup;
			while(pg != null)
			{
				if((!bIncludeTopMostGroup) && (pg.m_pParentGroup == null))
					break;

				strPath = pg.getName() + strSeparator + strPath;

				pg = pg.m_pParentGroup;
			}

			return strPath;
		}

		/// <summary>
		/// Assign new UUIDs to groups and entries.
		/// </summary>
		/// <param name="bNewGroups">Create new UUIDs for subgroups.</param>
		/// <param name="bNewEntries">Create new UUIDs for entries.</param>
		/// <param name="bRecursive">Recursive tree traversal.</param>
		public void CreateNewItemUuids(boolean bNewGroups, boolean bNewEntries, boolean bRecursive)
		{
			if(bNewGroups)
			{
				for(PwGroup pg : m_listGroups)
					pg.setUuid(new PwUuid(true));
			}

			if(bNewEntries)
			{
				for(PwEntry pe : m_listEntries)
					pe.SetUuid(new PwUuid(true), true);
			}

			if(bRecursive)
			{
				for(PwGroup pg : m_listGroups)
					pg.CreateNewItemUuids(bNewGroups, bNewEntries, true);
			}
		}

		public void TakeOwnership(boolean bTakeSubGroups, boolean bTakeEntries, boolean bRecursive)
		{
			if(bTakeSubGroups)
			{
				for(PwGroup pg : m_listGroups)
					pg.setParentGroup(this);
			}

			if(bTakeEntries)
			{
				for(PwEntry pe : m_listEntries)
					pe.setParentGroup(this);
			}

			if(bRecursive)
			{
				for(PwGroup pg : m_listGroups)
					pg.TakeOwnership(bTakeSubGroups, bTakeEntries, true);
			}
		}

		/// <summary>
		/// Find/create a subtree of groups.
		/// </summary>
		/// <param name="strTree">Tree String.</param>
		/// <param name="vSeparators">Separators that delimit groups in the
		/// <c>strTree</c> parameter.</param>
		public PwGroup FindCreateSubTree(String strTree, char[] vSeparators)
		{
			return FindCreateSubTree(strTree, vSeparators, true);
		}

		public PwGroup FindCreateSubTree(String strTree, char[] vSeparators,
			boolean bAllowCreate)
		{
			if(vSeparators == null) { assert false; vSeparators = new char[0]; }

			String[] v = new String[vSeparators.length];
			for(int i = 0; i < vSeparators.length; ++i)
				v[i] = String.valueOf(vSeparators[i]);

			return FindCreateSubTree(strTree, v, bAllowCreate);
		}

		public PwGroup FindCreateSubTree(String strTree, String[] vSeparators,
			boolean bAllowCreate)
		{
			assert strTree != null; if(strTree == null) return this;
			if(strTree.length() == 0) return this;

			String[] vGroups = strTree.split(Joiner.on("|").join(vSeparators));
			if((vGroups == null) || (vGroups.length == 0)) return this;

			PwGroup pgContainer = this;
			for(int nGroup = 0; nGroup < vGroups.length; ++nGroup)
			{
				if(Strings.isNullOrEmpty(vGroups[nGroup])) continue;

				boolean bFound = false;
				for(PwGroup pg : pgContainer.getGroups())
				{
					if(Objects.equal(pg.getName(), vGroups[nGroup]))
					{
						pgContainer = pg;
						bFound = true;
						break;
					}
				}

				if(!bFound)
				{
					if(!bAllowCreate) return null;

					PwGroup pg = new PwGroup(true, true, vGroups[nGroup], PwIcon.Folder);
					pgContainer.AddGroup(pg, true);
					pgContainer = pg;
				}
			}

			return pgContainer;
		}

		/// <summary>
		/// Get the level of the group (i.e. the number of parent groups).
		/// </summary>
		/// <returns>Number of parent groups.</returns>
		public int GetLevel()
		{
			PwGroup pg = m_pParentGroup;
			int uLevel = 0;

			while(pg != null)
			{
				pg = pg.getParentGroup();
				++uLevel;
			}

			return uLevel;
		}

		public String GetAutoTypeSequenceInherited()
		{
			if(m_strDefaultAutoTypeSequence.length() > 0)
				return m_strDefaultAutoTypeSequence;

			if(m_pParentGroup != null)
				return m_pParentGroup.GetAutoTypeSequenceInherited();

			return "";
		}

		public boolean GetAutoTypeEnabledInherited()
		{
            if (m_bEnableAutoType != null)
                return m_bEnableAutoType;

			if(m_pParentGroup != null)
				return m_pParentGroup.GetAutoTypeEnabledInherited();

			return DefaultAutoTypeEnabled;
		}

		public boolean GetSearchingEnabledInherited()
		{
            if (m_bEnableSearching != null)
                return m_bEnableSearching;

			if(m_pParentGroup != null)
				return m_pParentGroup.GetSearchingEnabledInherited();

			return DefaultSearchingEnabled;
		}

		/// <summary>
		/// Get a list of subgroups (not including this one).
		/// </summary>
		/// <param name="bRecursive">If <c>true</c>, subgroups are added
		/// recursively, i.e. all child groups are returned, too.</param>
		/// <returns>List of subgroups. If <paramref name="bRecursive" /> is
		/// <c>true</c>, it is guaranteed that subsubgroups appear after
		/// subgroups.</returns>
		public PwObjectList<PwGroup> GetGroups(boolean bRecursive)
		{
			if(!bRecursive) return m_listGroups;

			PwObjectList<PwGroup> list = m_listGroups.CloneShallow();
			for(PwGroup pgSub : m_listGroups)
			{
				list.Add(pgSub.GetGroups(true));
			}

			return list;
		}

		public PwObjectList<PwEntry> GetEntries(boolean bIncludeSubGroupEntries)
		{
			if(!bIncludeSubGroupEntries) return m_listEntries;

			PwObjectList<PwEntry> list = m_listEntries.CloneShallow();
			for(PwGroup pgSub : m_listGroups)
			{
				list.Add(pgSub.GetEntries(true));
			}

			return list;
		}

		/// <summary>
		/// Get objects contained in this group.
		/// </summary>
		/// <param name="bRecursive">Specifies whether to search recursively.</param>
		/// <param name="bEntries">If <c>null</c>, the returned list contains
		/// groups and entries. If <c>true</c>, the returned list contains only
		/// entries. If <c>false</c>, the returned list contains only groups.</param>
		/// <returns>List of objects.</returns>
		public List<IStructureItem> GetObjects(boolean bRecursive, Boolean bEntries)
		{
			List<IStructureItem> list = new ArrayList<IStructureItem>();

			if(bEntries == null || !bEntries)
			{
				PwObjectList<PwGroup> lGroups = GetGroups(bRecursive);
				for(PwGroup pg : lGroups) list.add(pg);
			}
            if (bEntries == null || bEntries) {
				PwObjectList<PwEntry> lEntries = GetEntries(bRecursive);
				for(PwEntry pe : lEntries) list.add(pe);
			}

			return list;
		}

		public boolean IsContainedIn(PwGroup pgContainer)
		{
			PwGroup pgCur = m_pParentGroup;
			while(pgCur != null)
			{
				if(pgCur == pgContainer) return true;

				pgCur = pgCur.m_pParentGroup;
			}

			return false;
		}

		/// <summary>
		/// Add a subgroup to this group.
		/// </summary>
		/// <param name="subGroup">Group to be added. Must not be <c>null</c>.</param>
		/// <param name="bTakeOwnership">If this parameter is <c>true</c>, the
		/// parent group reference of the subgroup will be set to the current
		/// group (i.e. the current group takes ownership of the subgroup).</param>
		public void AddGroup(PwGroup subGroup, boolean bTakeOwnership)
		{
			AddGroup(subGroup, bTakeOwnership, false);
		}

		/// <summary>
		/// Add a subgroup to this group.
		/// </summary>
		/// <param name="subGroup">Group to be added. Must not be <c>null</c>.</param>
		/// <param name="bTakeOwnership">If this parameter is <c>true</c>, the
		/// parent group reference of the subgroup will be set to the current
		/// group (i.e. the current group takes ownership of the subgroup).</param>
		/// <param name="bUpdateLocationChangedOfSub">If <c>true</c>, the
		/// <c>LocationChanged</c> property of the subgroup is updated.</param>
		public void AddGroup(PwGroup subGroup, boolean bTakeOwnership,
			boolean bUpdateLocationChangedOfSub)
		{
			if(subGroup == null) throw new IllegalArgumentException("subGroup");

			m_listGroups.Add(subGroup);

			if(bTakeOwnership) subGroup.m_pParentGroup = this;

			if(bUpdateLocationChangedOfSub) subGroup.setLocationChanged(new Date());
		}

		/// <summary>
		/// Add an entry to this group.
		/// </summary>
		/// <param name="pe">Entry to be added. Must not be <c>null</c>.</param>
		/// <param name="bTakeOwnership">If this parameter is <c>true</c>, the
		/// parent group reference of the entry will be set to the current
		/// group (i.e. the current group takes ownership of the entry).</param>
		public void AddEntry(PwEntry pe, boolean bTakeOwnership)
		{
			AddEntry(pe, bTakeOwnership, false);
		}

		/// <summary>
		/// Add an entry to this group.
		/// </summary>
		/// <param name="pe">Entry to be added. Must not be <c>null</c>.</param>
		/// <param name="bTakeOwnership">If this parameter is <c>true</c>, the
		/// parent group reference of the entry will be set to the current
		/// group (i.e. the current group takes ownership of the entry).</param>
		/// <param name="bUpdateLocationChangedOfEntry">If <c>true</c>, the
		/// <c>LocationChanged</c> property of the entry is updated.</param>
		public void AddEntry(PwEntry pe, boolean bTakeOwnership,
			boolean bUpdateLocationChangedOfEntry)
		{
			if(pe == null) throw new IllegalArgumentException("pe");

			m_listEntries.Add(pe);

			// Do not remove the entry from its previous parent group,
			// only assign it to the new one
			if(bTakeOwnership) pe.setParentGroup(this);

			if(bUpdateLocationChangedOfEntry) pe.setLocationChanged(new Date());
		}

		public void SortSubGroups(boolean bRecursive)
		{
			m_listGroups.Sort(new PwGroupComparer());

			if(bRecursive)
			{
				for(PwGroup pgSub : m_listGroups)
					pgSub.SortSubGroups(true);
			}
		}

		public void DeleteAllObjects(PwDatabase pdContext)
		{
			Date dtNow = new Date();

			for(PwEntry pe : m_listEntries)
			{
				PwDeletedObject pdo = new PwDeletedObject(pe.getUuid(), dtNow);
				pdContext.getDeletedObjects().Add(pdo);
			}
			m_listEntries.Clear();

			for(PwGroup pg : m_listGroups)
			{
				pg.DeleteAllObjects(pdContext);

				PwDeletedObject pdo = new PwDeletedObject(pg.getUuid(), dtNow);
				pdContext.getDeletedObjects().Add(pdo);
			}
			m_listGroups.Clear();
		}

		List<PwGroup> GetTopSearchSkippedGroups()
		{
			List<PwGroup> l = new ArrayList<PwGroup>();

			if(!GetSearchingEnabledInherited()) l.add(this);
			else GetTopSearchSkippedGroupsRec(l);

			return l;
		}

		private void GetTopSearchSkippedGroupsRec(List<PwGroup> l)
		{
			if(m_bEnableSearching != null && !m_bEnableSearching)
			{
				l.add(this);
				return;
			}
			else { assert GetSearchingEnabledInherited(); }

			for(PwGroup pgSub : m_listGroups)
				pgSub.GetTopSearchSkippedGroupsRec(l);
		}

		public void SetCreatedNow(boolean bRecursive)
		{
			final Date dt = new Date();

			m_tCreation = dt;
			m_tLastAccess = dt;

			if(!bRecursive) return;

			GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
			{
				pg.m_tCreation = dt;
				pg.m_tLastAccess = dt;
				return true;
			}};

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				pe.setCreationTime(dt);
				pe.setLastAccessTime(dt);
				return true;
			}};

			TraverseTree(TraversalMethod.PreOrder, gh, eh);
		}

		public PwGroup Duplicate()
		{
			PwGroup pg = CloneDeep();

			pg.setUuid(new PwUuid(true));
			pg.CreateNewItemUuids(true, true, true);

			pg.SetCreatedNow(true);

			pg.TakeOwnership(true, true, true);

			return pg;
		}
	}

	class PwGroupComparer implements Comparator<PwGroup>
	{
		public PwGroupComparer()
		{
		}

		public int compare(PwGroup a, PwGroup b)
		{
			return StrUtil.CompareNaturally(a.getName(), b.getName());
		}
	}
