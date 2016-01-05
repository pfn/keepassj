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
import com.google.common.base.Objects;
import com.google.common.base.Strings;

/// <summary>
	/// A class representing a password entry. A password entry consists of several
	/// fields like title, user name, password, etc. Each password entry has a
	/// unique ID (UUID).
	/// </summary>
	public class PwEntry implements ITimeLogger, IStructureItem, IDeepCloneable<PwEntry>
	{
		private PwUuid m_uuid = PwUuid.Zero;
		private PwGroup m_pParentGroup = null;
		private Date m_tParentGroupLastMod = PwDefs.DtDefaultNow;

		private ProtectedStringDictionary m_listStrings = new ProtectedStringDictionary();
		private ProtectedBinaryDictionary m_listBinaries = new ProtectedBinaryDictionary();
		private AutoTypeConfig m_listAutoType = new AutoTypeConfig();
		private PwObjectList<PwEntry> m_listHistory = new PwObjectList<PwEntry>();

		private PwIcon m_pwIcon = PwIcon.Key;
		private PwUuid m_pwCustomIconID = PwUuid.Zero;

		private Color m_clrForeground = Color.Empty;
		private Color m_clrBackground = Color.Empty;

		private Date m_tCreation = PwDefs.DtDefaultNow;
		private Date m_tLastMod = PwDefs.DtDefaultNow;
		private Date m_tLastAccess = PwDefs.DtDefaultNow;
		private Date m_tExpire = PwDefs.DtDefaultNow;
		private boolean m_bExpires = false;
		private long m_uUsageCount = 0;

		private String m_strOverrideUrl = "";

		private List<String> m_vTags = new ArrayList<String>();

		/// <summary>
		/// UUID of this entry.
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
		/// Reference to a group which contains the current entry.
		/// </summary>
		public PwGroup getParentGroup()
		{
			return m_pParentGroup;

		}
			// Plugins: use <c>PwGroup.AddEntry</c> instead.
			public void setParentGroup(PwGroup value) { m_pParentGroup = value; }

		/// <summary>
		/// The date/time when the location of the object was last changed.
		/// </summary>
		public Date getLocationChanged()
		{
			return m_tParentGroupLastMod;
		}
			public void setLocationChanged(Date value) { m_tParentGroupLastMod = value; }

		/// <summary>
		/// Get or set all entry strings.
		/// </summary>
		public ProtectedStringDictionary getStrings()
		{
			return m_listStrings;
		}
			public void setStrings(ProtectedStringDictionary value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_listStrings = value;
			}

		/// <summary>
		/// Get or set all entry binaries.
		/// </summary>
		public ProtectedBinaryDictionary getBinaries()
		{
			return m_listBinaries;
		}
			public void setBinaries(ProtectedBinaryDictionary value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_listBinaries = value;
			}

		/// <summary>
		/// Get or set all auto-type window/keystroke sequence associations.
		/// </summary>
		public AutoTypeConfig getAutoType()
		{
			return m_listAutoType;
		}
			public void setAutoType(AutoTypeConfig value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_listAutoType = value;
			}

		/// <summary>
		/// Get all previous versions of this entry (backups).
		/// </summary>
		public PwObjectList<PwEntry> getHistory()
		{
			return m_listHistory;
		}
			public void setHistory(PwObjectList<PwEntry> value)
			{
				assert value != null; if(value == null) throw new IllegalArgumentException("value");
				m_listHistory = value;
			}

		/// <summary>
		/// Image ID specifying the icon that will be used for this entry.
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
		/// Get or set the foreground color of this entry.
		/// </summary>
		public Color getForegroundColor()
		{
			return m_clrForeground;
		}
			public void setForegroundColor(Color value) { m_clrForeground = value; }

		/// <summary>
		/// Get or set the background color of this entry.
		/// </summary>
		public Color getBackgroundColor()
		{
			return m_clrBackground;
		}
			public void setBackgroundColor(Color value) { m_clrBackground = value; }

		/// <summary>
		/// The date/time when this entry was created.
		/// </summary>
		public Date getCreationTime()
		{
			return m_tCreation;
		}
			public void setCreationTime(Date value) { m_tCreation = value; }

		/// <summary>
		/// The date/time when this entry was last modified.
		/// </summary>
		public Date getLastModificationTime()
		{
			return m_tLastMod;
		}
			public void setLastModificationTime(Date value) { m_tLastMod = value; }

		/// <summary>
		/// The date/time when this entry was last accessed (read).
		/// </summary>
		public Date getLastAccessTime()
		{
			return m_tLastAccess;
		}
			public void setLastAccessTime(Date value) { m_tLastAccess = value; }

		/// <summary>
		/// The date/time when this entry expires. Use the <c>Expires</c> property
		/// to specify if the entry does actually expire or not.
		/// </summary>
		public Date getExpiryTime()
		{
			return m_tExpire;
		}
			public void setExpiryTime(Date value) { m_tExpire = value; }

		/// <summary>
		/// Specifies whether the entry expires or not.
		/// </summary>
		public boolean getExpires()
		{
			return m_bExpires;
		}
			public void setExpires(boolean value) { m_bExpires = value; }

		/// <summary>
		/// Get or set the usage count of the entry. To increase the usage
		/// count by one, use the <c>Touch</c> function.
		/// </summary>
		public long getUsageCount()
		{
			return m_uUsageCount;
		}
			public void setUsageCount(long value) { m_uUsageCount = value; }

		/// <summary>
		/// Entry-specific override URL. If this String is non-empty,
		/// </summary>
		public String getOverrideUrl()
		{
			return m_strOverrideUrl;
		}
			public void setOverrideUrl(String value)
			{
				if(value == null) throw new IllegalArgumentException("value");
				m_strOverrideUrl = value;
			}

		/// <summary>
		/// List of tags associated with this entry.
		/// </summary>
		public List<String> getTags()
		{
			return m_vTags;
		}
			public void setTags(List<String> value)
			{
				if(value == null) throw new IllegalArgumentException("value");
				m_vTags = value;
			}

		public static List<EventHandler<ObjectTouchedEventArgs>> EntryTouched = new ArrayList<>();
		public List<EventHandler<ObjectTouchedEventArgs>> Touched = new ArrayList<>();

		/// <summary>
		/// Construct a new, empty password entry. Member variables will be initialized
		/// to their default values.
		/// </summary>
		/// <param name="bCreateNewUuid">If <c>true</c>, a new UUID will be created
		/// for this entry. If <c>false</c>, the UUID is zero and you must set it
		/// manually later.</param>
		/// <param name="bSetTimes">If <c>true</c>, the creation, last modification
		/// and last access times will be set to the current system time.</param>
		public PwEntry(boolean bCreateNewUuid, boolean bSetTimes)
		{
			if(bCreateNewUuid) m_uuid = new PwUuid(true);

			if(bSetTimes)
			{
				m_tCreation = m_tLastMod = m_tLastAccess =
					m_tParentGroupLastMod = new Date();
			}
		}

		/// <summary>
		/// Construct a new, empty password entry. Member variables will be initialized
		/// to their default values.
		/// </summary>
		/// <param name="pwParentGroup">Reference to the containing group, this
		/// parameter may be <c>null</c> and set later manually.</param>
		/// <param name="bCreateNewUuid">If <c>true</c>, a new UUID will be created
		/// for this entry. If <c>false</c>, the UUID is zero and you must set it
		/// manually later.</param>
		/// <param name="bSetTimes">If <c>true</c>, the creation, last modification
		/// and last access times will be set to the current system time.</param>
		@Deprecated//("Use a different constructor. To add an entry to a group, use AddEntry of PwGroup.")
		public PwEntry(PwGroup pwParentGroup, boolean bCreateNewUuid, boolean bSetTimes)
		{
			m_pParentGroup = pwParentGroup;

			if(bCreateNewUuid) m_uuid = new PwUuid(true);

			if(bSetTimes)
			{
				m_tCreation = m_tLastMod = m_tLastAccess =
					m_tParentGroupLastMod = new Date();
			}
		}

		/// <summary>
		/// Clone the current entry. The returned entry is an exact value copy
		/// of the current entry (including UUID and parent group reference).
		/// All mutable members are cloned.
		/// </summary>
		/// <returns>Exact value clone. All references to mutable values changed.</returns>
		public PwEntry CloneDeep()
		{
			PwEntry peNew = new PwEntry(false, false);

			peNew.m_uuid = m_uuid; // PwUuid is immutable
			peNew.m_pParentGroup = m_pParentGroup;
			peNew.m_tParentGroupLastMod = m_tParentGroupLastMod;

			peNew.m_listStrings = m_listStrings.CloneDeep();
			peNew.m_listBinaries = m_listBinaries.CloneDeep();
			peNew.m_listAutoType = m_listAutoType.CloneDeep();
			peNew.m_listHistory = m_listHistory.CloneDeep();

			peNew.m_pwIcon = m_pwIcon;
			peNew.m_pwCustomIconID = m_pwCustomIconID;

			peNew.m_clrForeground = m_clrForeground;
			peNew.m_clrBackground = m_clrBackground;

			peNew.m_tCreation = m_tCreation;
			peNew.m_tLastMod = m_tLastMod;
			peNew.m_tLastAccess = m_tLastAccess;
			peNew.m_tExpire = m_tExpire;
			peNew.m_bExpires = m_bExpires;
			peNew.m_uUsageCount = m_uUsageCount;

			peNew.m_strOverrideUrl = m_strOverrideUrl;

			peNew.m_vTags = new ArrayList<String>(m_vTags);

			return peNew;
		}

		public PwEntry CloneStructure()
		{
			PwEntry peNew = new PwEntry(false, false);

			peNew.m_uuid = m_uuid; // PwUuid is immutable
			peNew.m_tParentGroupLastMod = m_tParentGroupLastMod;
			// Do not assign m_pParentGroup

			return peNew;
		}

		private static PwCompareOptions.Options BuildCmpOpt(boolean bIgnoreParentGroup,
			boolean bIgnoreLastMod, boolean bIgnoreLastAccess, boolean bIgnoreHistory,
			boolean bIgnoreThisLastBackup)
		{
			PwCompareOptions.Options pwOpt = PwCompareOptions.or(PwCompareOptions.None);
			if(bIgnoreParentGroup) pwOpt.or(PwCompareOptions.IgnoreParentGroup);
			if(bIgnoreLastMod) pwOpt.or(PwCompareOptions.IgnoreLastMod);
			if(bIgnoreLastAccess) pwOpt.or(PwCompareOptions.IgnoreLastAccess);
			if(bIgnoreHistory) pwOpt.or(PwCompareOptions.IgnoreHistory);
			if(bIgnoreThisLastBackup) pwOpt.or(PwCompareOptions.IgnoreLastBackup);
			return pwOpt;
		}

		@Deprecated
		public boolean EqualsEntry(PwEntry pe, boolean bIgnoreParentGroup, boolean bIgnoreLastMod,
			boolean bIgnoreLastAccess, boolean bIgnoreHistory, boolean bIgnoreThisLastBackup)
		{
			return EqualsEntry(pe, BuildCmpOpt(bIgnoreParentGroup, bIgnoreLastMod,
				bIgnoreLastAccess, bIgnoreHistory, bIgnoreThisLastBackup),
				MemProtCmpMode.None);
		}

		@Deprecated
		public boolean EqualsEntry(PwEntry pe, boolean bIgnoreParentGroup, boolean bIgnoreLastMod,
			boolean bIgnoreLastAccess, boolean bIgnoreHistory, boolean bIgnoreThisLastBackup,
			MemProtCmpMode mpCmpStr)
		{
			return EqualsEntry(pe, BuildCmpOpt(bIgnoreParentGroup, bIgnoreLastMod,
				bIgnoreLastAccess, bIgnoreHistory, bIgnoreThisLastBackup), mpCmpStr);
		}

		public boolean EqualsEntry(PwEntry pe, PwCompareOptions.Options pwOpt,
			MemProtCmpMode mpCmpStr)
		{
			if(pe == null) { assert false; return false; }

			boolean bNeEqStd = pwOpt.contains(PwCompareOptions.NullEmptyEquivStd);
			boolean bIgnoreLastAccess = pwOpt.contains(PwCompareOptions.IgnoreLastAccess);
			boolean bIgnoreLastMod = pwOpt.contains(PwCompareOptions.IgnoreLastMod);

			if(!m_uuid.Equals(pe.m_uuid)) return false;
			if(!pwOpt.contains(PwCompareOptions.IgnoreParentGroup))
			{
				if(m_pParentGroup != pe.m_pParentGroup) return false;
				if(!bIgnoreLastMod && (m_tParentGroupLastMod != pe.m_tParentGroupLastMod))
					return false;
			}

			if(!m_listStrings.EqualsDictionary(pe.m_listStrings, pwOpt, mpCmpStr))
				return false;
			if(!m_listBinaries.EqualsDictionary(pe.m_listBinaries)) return false;

			if(!m_listAutoType.Equals(pe.m_listAutoType)) return false;

			if(pwOpt.contains(PwCompareOptions.IgnoreHistory))
			{
				boolean bIgnoreLastBackup = pwOpt.contains(PwCompareOptions.IgnoreLastBackup);

				if(!bIgnoreLastBackup && (m_listHistory.getUCount() != pe.m_listHistory.getUCount()))
					return false;
				if(bIgnoreLastBackup && (m_listHistory.getUCount() == 0))
				{
					assert false;
					return false;
				}
				if(bIgnoreLastBackup && ((m_listHistory.getUCount() - 1) != pe.m_listHistory.getUCount()))
					return false;

				PwCompareOptions.Options cmpSub = PwCompareOptions.or(PwCompareOptions.IgnoreParentGroup);
				if(bNeEqStd) cmpSub.or(PwCompareOptions.NullEmptyEquivStd);
				if(bIgnoreLastMod) cmpSub.or(PwCompareOptions.IgnoreLastMod);
				if(bIgnoreLastAccess) cmpSub.or(PwCompareOptions.IgnoreLastAccess);

				for(int uHist = 0; uHist < pe.m_listHistory.getUCount(); ++uHist)
				{
					if(!m_listHistory.GetAt(uHist).EqualsEntry(pe.m_listHistory.GetAt(
						uHist), cmpSub, MemProtCmpMode.None))
						return false;
				}
			}

			if(m_pwIcon != pe.m_pwIcon) return false;
			if(!m_pwCustomIconID.Equals(pe.m_pwCustomIconID)) return false;

			if(m_clrForeground != pe.m_clrForeground) return false;
			if(m_clrBackground != pe.m_clrBackground) return false;

			if(m_tCreation != pe.m_tCreation) return false;
			if(!bIgnoreLastMod && (m_tLastMod != pe.m_tLastMod)) return false;
			if(!bIgnoreLastAccess && (m_tLastAccess != pe.m_tLastAccess)) return false;
			if(m_tExpire != pe.m_tExpire) return false;
			if(m_bExpires != pe.m_bExpires) return false;
			if(!bIgnoreLastAccess && (m_uUsageCount != pe.m_uUsageCount)) return false;

			if(!Objects.equal(m_strOverrideUrl, pe.m_strOverrideUrl)) return false;

			if(m_vTags.size() != pe.m_vTags.size()) return false;
			for(int iTag = 0; iTag < m_vTags.size(); ++iTag)
			{
				if(!Objects.equal(m_vTags.get(iTag), pe.m_vTags.get(iTag))) return false;
			}

			return true;
		}

		/// <summary>
		/// Assign properties to the current entry based on a template entry.
		/// </summary>
		/// <param name="peTemplate">Template entry. Must not be <c>null</c>.</param>
		/// <param name="bOnlyIfNewer">Only set the properties of the template entry
		/// if it is newer than the current one.</param>
		/// <param name="bIncludeHistory">If <c>true</c>, the history will be
		/// copied, too.</param>
		/// <param name="bAssignLocationChanged">If <c>true</c>, the
		/// <c>LocationChanged</c> property is copied, otherwise not.</param>
		public void AssignProperties(PwEntry peTemplate, boolean bOnlyIfNewer,
			boolean bIncludeHistory, boolean bAssignLocationChanged)
		{
			assert peTemplate != null; if(peTemplate == null) throw new IllegalArgumentException("peTemplate");

			if(bOnlyIfNewer && (TimeUtil.Compare(peTemplate.m_tLastMod, m_tLastMod,
				true) < 0))
				return;

			// Template UUID should be the same as the current one
			assert m_uuid.Equals(peTemplate.m_uuid);
			m_uuid = peTemplate.m_uuid;

			if(bAssignLocationChanged)
				m_tParentGroupLastMod = peTemplate.m_tParentGroupLastMod;

			m_listStrings = peTemplate.m_listStrings;
			m_listBinaries = peTemplate.m_listBinaries;
			m_listAutoType = peTemplate.m_listAutoType;
			if(bIncludeHistory) m_listHistory = peTemplate.m_listHistory;

			m_pwIcon = peTemplate.m_pwIcon;
			m_pwCustomIconID = peTemplate.m_pwCustomIconID; // Immutable

			m_clrForeground = peTemplate.m_clrForeground;
			m_clrBackground = peTemplate.m_clrBackground;

			m_tCreation = peTemplate.m_tCreation;
			m_tLastMod = peTemplate.m_tLastMod;
			m_tLastAccess = peTemplate.m_tLastAccess;
			m_tExpire = peTemplate.m_tExpire;
			m_bExpires = peTemplate.m_bExpires;
			m_uUsageCount = peTemplate.m_uUsageCount;

			m_strOverrideUrl = peTemplate.m_strOverrideUrl;

			m_vTags = new ArrayList<String>(peTemplate.m_vTags);
		}

		/// <summary>
		/// Touch the entry. This function updates the internal last access
		/// time. If the <paramref name="bModified" /> parameter is <c>true</c>,
		/// the last modification time gets updated, too.
		/// </summary>
		/// <param name="bModified">Modify last modification time.</param>
		public void Touch(boolean bModified)
		{
			Touch(bModified, true);
		}

		/// <summary>
		/// Touch the entry. This function updates the internal last access
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
			for (EventHandler<ObjectTouchedEventArgs> h : PwEntry.EntryTouched)
				h.delegate(this, new ObjectTouchedEventArgs(this,
					bModified, bTouchParents));

			if(bTouchParents && (m_pParentGroup != null))
				m_pParentGroup.Touch(bModified, true);
		}

		/// <summary>
		/// Create a backup of this entry. The backup item doesn't contain any
		/// history items.
		/// </summary>
		@Deprecated
		public void CreateBackup()
		{
			CreateBackup(null);
		}

		/// <summary>
		/// Create a backup of this entry. The backup item doesn't contain any
		/// history items.
		/// <param name="pwHistMntcSettings">If this parameter isn't <c>null</c>,
		/// the history list is maintained automatically (i.e. old backups are
		/// deleted if there are too many or the history size is too large).
		/// This parameter may be <c>null</c> (no maintenance then).</param>
		/// </summary>
		public void CreateBackup(PwDatabase pwHistMntcSettings)
		{
			PwEntry peCopy = CloneDeep();
			peCopy.setHistory(new PwObjectList<PwEntry>()); // Remove history

			m_listHistory.Add(peCopy); // Must be added at end, see EqualsEntry

			if(pwHistMntcSettings != null) MaintainBackups(pwHistMntcSettings);
		}

		/// <summary>
		/// Restore an entry snapshot from backups.
		/// </summary>
		/// <param name="uBackupIndex">Index of the backup item, to which
		/// should be reverted.</param>
		@Deprecated
		public void RestoreFromBackup(int uBackupIndex)
		{
			RestoreFromBackup(uBackupIndex, null);
		}

		/// <summary>
		/// Restore an entry snapshot from backups.
		/// </summary>
		/// <param name="uBackupIndex">Index of the backup item, to which
		/// should be reverted.</param>
		/// <param name="pwHistMntcSettings">If this parameter isn't <c>null</c>,
		/// the history list is maintained automatically (i.e. old backups are
		/// deleted if there are too many or the history size is too large).
		/// This parameter may be <c>null</c> (no maintenance then).</param>
		public void RestoreFromBackup(int uBackupIndex, PwDatabase pwHistMntcSettings)
		{
			assert uBackupIndex < m_listHistory.getUCount();
			if(uBackupIndex >= m_listHistory.getUCount())
				throw new ArrayIndexOutOfBoundsException("uBackupIndex");

			PwEntry pe = m_listHistory.GetAt(uBackupIndex);
			assert pe != null; if(pe == null) throw new UnsupportedOperationException();

			CreateBackup(pwHistMntcSettings); // Backup current data before restoring
			AssignProperties(pe, false, false, false);
		}

		public boolean HasBackupOfData(PwEntry peData, boolean bIgnoreLastMod,
			boolean bIgnoreLastAccess)
		{
			if(peData == null) { assert false; return false; }

			PwCompareOptions.Options cmpOpt = PwCompareOptions.or(PwCompareOptions.IgnoreParentGroup,
				PwCompareOptions.IgnoreHistory, PwCompareOptions.NullEmptyEquivStd);
			if(bIgnoreLastMod) cmpOpt.or(PwCompareOptions.IgnoreLastMod);
			if(bIgnoreLastAccess) cmpOpt.or(PwCompareOptions.IgnoreLastAccess);

			for(PwEntry pe : m_listHistory)
			{
				if(pe.EqualsEntry(peData, cmpOpt, MemProtCmpMode.None)) return true;
			}

			return false;
		}

		/// <summary>
		/// Delete old history items if there are too many or the history
		/// size is too large.
		/// <returns>If one or more history items have been deleted, <c>true</c>
		/// is returned. Otherwise <c>false</c>.</returns>
		/// </summary>
		public boolean MaintainBackups(PwDatabase pwSettings)
		{
			if(pwSettings == null) { assert false; return false; }

			boolean bDeleted = false;

			int nMaxItems = pwSettings.getHistoryMaxItems();
			if(nMaxItems >= 0)
			{
				while(m_listHistory.getUCount() > nMaxItems)
				{
					RemoveOldestBackup();
					bDeleted = true;
				}
			}

			long lMaxSize = pwSettings.getHistoryMaxSize();
			if(lMaxSize >= 0)
			{
				while(true)
				{
					long uHistSize = 0;
					for(PwEntry pe : m_listHistory) { uHistSize += pe.GetSize(); }

					if(uHistSize > (long)lMaxSize)
					{
						RemoveOldestBackup();
						bDeleted = true;
					}
					else break;
				}
			}

			return bDeleted;
		}

		private void RemoveOldestBackup()
		{
			Date dtMin = new Date(Long.MAX_VALUE);
			int idxRemove = Integer.MAX_VALUE;

			for(int u = 0; u < m_listHistory.getUCount(); ++u)
			{
				PwEntry pe = m_listHistory.GetAt(u);
				if(TimeUtil.Compare(pe.getLastModificationTime(), dtMin, true) < 0)
				{
					idxRemove = u;
					dtMin = pe.getLastModificationTime();
				}
			}

			if(idxRemove != Integer.MAX_VALUE) m_listHistory.RemoveAt(idxRemove);
		}

		public boolean GetAutoTypeEnabled()
		{
			if(!m_listAutoType.isEnabled()) return false;

			if(m_pParentGroup != null)
				return m_pParentGroup.GetAutoTypeEnabledInherited();

			return PwGroup.DefaultAutoTypeEnabled;
		}

		public String GetAutoTypeSequence()
		{
			String strSeq = m_listAutoType.getDefaultSequence();

			PwGroup pg = m_pParentGroup;
			while(pg != null)
			{
				if(strSeq.length() != 0) break;

				strSeq = pg.getDefaultAutoTypeSequence();
				pg = pg.getParentGroup();
			}

			if(strSeq.length() != 0) return strSeq;

			if(PwDefs.IsTanEntry(this)) return PwDefs.DefaultAutoTypeSequenceTan;
			return PwDefs.DefaultAutoTypeSequence;
		}

		public boolean GetSearchingEnabled()
		{
			if(m_pParentGroup != null)
				return m_pParentGroup.GetSearchingEnabledInherited();

			return PwGroup.DefaultSearchingEnabled;
		}

		/// <summary>
		/// Approximate the total size of this entry in bytes (including
		/// strings, binaries and history entries).
		/// </summary>
		/// <returns>Size in bytes.</returns>
		public long GetSize()
		{
			long uSize = 128; // Approx fixed length data

			for(Map.Entry<String, ProtectedString> kvpStr : m_listStrings)
			{
				uSize += (long)kvpStr.getKey().length();
				uSize += (long)kvpStr.getValue().Length();
			}

			for(Map.Entry<String, ProtectedBinary> kvpBin : m_listBinaries)
			{
				uSize += (long)kvpBin.getKey().length();
				uSize += kvpBin.getValue().getLength();
			}

			uSize += (long)m_listAutoType.getDefaultSequence().length();
			for(AutoTypeAssociation a : m_listAutoType.getAssociations())
			{
				uSize += (long)a.getWindowName().length();
				uSize += (long)a.getSequence().length();
			}

			for(PwEntry peHistory : m_listHistory)
				uSize += peHistory.GetSize();

			uSize += (long)m_strOverrideUrl.length();

			for(String strTag : m_vTags)
				uSize += (long)strTag.length();

			return uSize;
		}

		public boolean HasTag(String strTag)
		{
			if(Strings.isNullOrEmpty(strTag)) { assert false; return false; }

            for (String m_vTag : m_vTags) {
                if (m_vTag.equalsIgnoreCase(strTag)) return true;
            }

			return false;
		}

		public boolean AddTag(String strTag)
		{
			if(Strings.isNullOrEmpty(strTag)) { assert false; return false; }

            for (String m_vTag : m_vTags) {
                if (m_vTag.equalsIgnoreCase(strTag)) return false;
            }

			m_vTags.add(strTag);
			return true;
		}

		public boolean RemoveTag(String strTag)
		{
			if(Strings.isNullOrEmpty(strTag)) { assert false; return false; }

			for(int i = 0; i < m_vTags.size(); ++i)
			{
				if(m_vTags.get(i).equalsIgnoreCase(strTag))
				{
					m_vTags.remove(i);
					return true;
				}
			}

			return false;
		}

		public boolean IsContainedIn(PwGroup pgContainer)
		{
			PwGroup pgCur = m_pParentGroup;
			while(pgCur != null)
			{
				if(pgCur == pgContainer) return true;

				pgCur = pgCur.getParentGroup();
			}

			return false;
		}

		public void SetUuid(PwUuid pwNewUuid, boolean bAlsoChangeHistoryUuids)
		{
			this.setUuid(pwNewUuid);

			if(bAlsoChangeHistoryUuids)
			{
				for(PwEntry peHist : m_listHistory)
				{
					peHist.setUuid(pwNewUuid);
				}
			}
		}

		public void SetCreatedNow()
		{
			Date dt = new Date();

			m_tCreation = dt;
			m_tLastAccess = dt;
		}

		public PwEntry Duplicate()
		{
			PwEntry pe = CloneDeep();

			pe.SetUuid(new PwUuid(true), true);
			pe.SetCreatedNow();

			return pe;
		}
	}

	class PwEntryComparer implements Comparator<PwEntry>
	{
		private String m_strFieldName;
		private boolean m_bCaseInsensitive;
		private boolean m_bCompareNaturally;

		public PwEntryComparer(String strFieldName, boolean bCaseInsensitive,
			boolean bCompareNaturally)
		{
			if(strFieldName == null) throw new IllegalArgumentException("strFieldName");

			m_strFieldName = strFieldName;
			m_bCaseInsensitive = bCaseInsensitive;
			m_bCompareNaturally = bCompareNaturally;
		}

		public int compare(PwEntry a, PwEntry b)
		{
			String strA = a.getStrings().ReadSafe(m_strFieldName);
			String strB = b.getStrings().ReadSafe(m_strFieldName);

			if(m_bCompareNaturally) return StrUtil.CompareNaturally(strA, strB);

			return strA.toLowerCase().compareTo(strB.toLowerCase());
		}
	}
