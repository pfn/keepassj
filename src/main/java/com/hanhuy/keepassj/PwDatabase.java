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

import com.google.common.base.Objects;
import com.google.common.base.Predicate;
import com.google.common.collect.Maps;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;

/// <summary>
/// The core password manager class. It contains a number of groups, which
/// contain the actual entries.
/// </summary>
public class PwDatabase
{
	final static int DefaultHistoryMaxItems = 10; // -1 = unlimited
	final static long DefaultHistoryMaxSize = 6 * 1024 * 1024; // -1 = unlimited

	private static boolean m_bPrimaryCreated = false;

	// Initializations see Clear()
	private PwGroup m_pgRootGroup = null;
	private PwObjectList<PwDeletedObject> m_vDeletedObjects = new PwObjectList<PwDeletedObject>();

	private PwUuid m_uuidDataCipher = StandardAesEngine.getAesUuid();
	private PwCompressionAlgorithm m_caCompression = PwCompressionAlgorithm.GZip;
	private long m_uKeyEncryptionRounds = PwDefs.DefaultKeyEncryptionRounds;

	private CompositeKey m_pwUserKey = null;
	private MemoryProtectionConfig m_memProtConfig = new MemoryProtectionConfig();

	private List<PwCustomIcon> m_vCustomIcons = new ArrayList<PwCustomIcon>();
	private boolean m_bUINeedsIconUpdate = true;

	private String m_strName = "";
	private Date m_dtNameChanged = PwDefs.DtDefaultNow;
	private String m_strDesc = "";
	private Date m_dtDescChanged = PwDefs.DtDefaultNow;
	private String m_strDefaultUserName = "";
	private Date m_dtDefaultUserChanged = PwDefs.DtDefaultNow;
	private int m_uMntncHistoryDays = 365;
	private Color m_clr = Color.Empty;

	private Date m_dtKeyLastChanged = PwDefs.DtDefaultNow;
	private long m_lKeyChangeRecDays = -1;
	private long m_lKeyChangeForceDays = -1;

	private IOConnectionInfo m_ioSource = new IOConnectionInfo();
	private boolean m_bDatabaseOpened = false;
	private boolean m_bModified = false;

	private PwUuid m_pwLastSelectedGroup = PwUuid.Zero;
	private PwUuid m_pwLastTopVisibleGroup = PwUuid.Zero;

	private boolean m_bUseRecycleBin = true;
	private PwUuid m_pwRecycleBin = PwUuid.Zero;
	private Date m_dtRecycleBinChanged = PwDefs.DtDefaultNow;
	private PwUuid m_pwEntryTemplatesGroup = PwUuid.Zero;
	private Date m_dtEntryTemplatesChanged = PwDefs.DtDefaultNow;

	private int m_nHistoryMaxItems = DefaultHistoryMaxItems;
	private long m_lHistoryMaxSize = DefaultHistoryMaxSize; // In bytes

	private StringDictionaryEx m_vCustomData = new StringDictionaryEx();

	private byte[] m_pbHashOfFileOnDisk = null;
	private byte[] m_pbHashOfLastIO = null;

	private boolean m_bUseFileTransactions = false;
	private boolean m_bUseFileLocks = false;

	private IStatusLogger m_slStatus = null;

	private static String m_strLocalizedAppName = "";

	// private const string StrBackupExtension = ".bak";

	/// <summary>
	/// Get the root group that contains all groups and entries stored in the
	/// database.
	/// </summary>
	/// <returns>Root group. The return value is <c>null</c>, if no database
	/// has been opened.</returns>
	public PwGroup getRootGroup()
	{
		return m_pgRootGroup;
	}
	public void setRootGroup(PwGroup value)
    {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");

        m_pgRootGroup = value;
    }

	/// <summary>
	/// <c>IOConnection</c> of the currently opened database file.
	/// Is never <c>null</c>.
	/// </summary>
	public IOConnectionInfo getIOConnectionInfo()
	{
		return m_ioSource;
	}

	/// <summary>
	/// If this is <c>true</c>, a database is currently open.
	/// </summary>
	public boolean IsOpen()
	{
		return m_bDatabaseOpened;
	}

	/// <summary>
	/// Modification flag. If true, the class has been modified and the
	/// user interface should prompt the user to save the changes before
	/// closing the database for example.
	/// </summary>
	public boolean isModified()
	{
		return m_bModified;
	}

    public void setModified(boolean value) {
		m_bModified = value;
    }


	/// <summary>
	/// The user key used for database encryption. This key must be created
	/// and set before using any of the database load/save functions.
	/// </summary>
	public CompositeKey getMasterKey()
	{
		return m_pwUserKey;
	}
    public void setMasterKey(CompositeKey value) {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");

        m_pwUserKey = value;
    }

	/// <summary>
	/// Name of the database.
	/// </summary>
	public String getName()
	{
		return m_strName;
	}
    public void setName(String value) {
        assert value != null;
        if(value != null) m_strName = value;
    }

	public Date getNameChanged()
	{
		return m_dtNameChanged;
	}
    public void setNameChanged(Date value) {
		m_dtNameChanged = value;
    }

	/// <summary>
	/// Database description.
	/// </summary>
	public String getDescription()
	{
		return m_strDesc;
	}
    public void setDescription(String value) {
        assert value != null;
        if(value != null) m_strDesc = value;
    }

	public Date getDescriptionChanged()
	{
		return m_dtDescChanged;
	}
    public void setDescriptionChanged(Date value) {
		m_dtDescChanged = value;
    }

	/// <summary>
	/// Default user name used for new entries.
	/// </summary>
	public String getDefaultUserName()
	{
		return m_strDefaultUserName;
	}
    public void setDefaultUserName(String value)
    {
        assert value != null;
        if(value != null) m_strDefaultUserName = value;
    }

	public Date getDefaultUserNameChanged()
	{
		return m_dtDefaultUserChanged;
	}
	public void setDefaultUserNameChanged(Date value) {
		m_dtDefaultUserChanged = value;
    }

	/// <summary>
	/// Number of days until history entries are being deleted
	/// in a database maintenance operation.
	/// </summary>
	public int getMaintenanceHistoryDays()
	{
		return m_uMntncHistoryDays;
	}
    public void setMaintenanceHistoryDays(int value) {
		m_uMntncHistoryDays = value;
    }

	public Color getColor()
	{
		return m_clr;
	}
    public void setColor(Color value) {
		m_clr = value;
    }

	public Date getMasterKeyChanged()
	{
		return m_dtKeyLastChanged;
	}
    public void setMasterKeyChanged(Date value) {
		m_dtKeyLastChanged = value;
    }

	public long getMasterKeyChangeRec()
	{
		return m_lKeyChangeRecDays;
	}
    public void setMasterKeyChangeRec(long value) {
		m_lKeyChangeRecDays = value;
    }

	public long getMasterKeyChangeForce()
	{
		return m_lKeyChangeForceDays;
	}
    public void setMasterKeyChangeForce(long value) {
		m_lKeyChangeForceDays = value;
    }

	/// <summary>
	/// The encryption algorithm used to encrypt the data part of the database.
	/// </summary>
	public PwUuid getDataCipherUuid()
	{
		return m_uuidDataCipher;
	}
	public void setDataCipherUuid(PwUuid value)
    {
        assert value != null;
        if(value != null) m_uuidDataCipher = value;
    }

	/// <summary>
	/// Compression algorithm used to encrypt the data part of the database.
	/// </summary>
	public PwCompressionAlgorithm getCompression()
	{
		return m_caCompression;
	}
    public void setCompression(PwCompressionAlgorithm value) {
		m_caCompression = value;
    }

	/// <summary>
	/// Number of key transformation rounds (in order to make dictionary
	/// attacks harder).
	/// </summary>
	public long getKeyEncryptionRounds()
	{
		return m_uKeyEncryptionRounds;
	}
	public void setKeyEncryptionRounds(long value) {
	    m_uKeyEncryptionRounds = value;
    }

	/// <summary>
	/// Memory protection configuration (for default fields).
	/// </summary>
	public MemoryProtectionConfig getMemoryProtection()
	{
		return m_memProtConfig;
	}
    public void setMemoryProtection(MemoryProtectionConfig value)
    {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");

        m_memProtConfig = value;
    }

	/// <summary>
	/// Get a list of all deleted objects.
	/// </summary>
	public PwObjectList<PwDeletedObject> getDeletedObjects()
	{
		return m_vDeletedObjects;
	}

	/// <summary>
	/// Get all custom icons stored in this database.
	/// </summary>
	public List<PwCustomIcon> getCustomIcons()
	{
		return m_vCustomIcons;
	}

	/// <summary>
	/// This is a dirty-flag for the UI. It is used to indicate when an
	/// icon list update is required.
	/// </summary>
	public boolean getUINeedsIconUpdate()
	{
		return m_bUINeedsIconUpdate;
	}
	public void setUINeedsIconUpdte(boolean value) { m_bUINeedsIconUpdate = value; }

	public PwUuid getLastSelectedGroup()
	{
		return m_pwLastSelectedGroup;
	}
    public void setLastSelectedGroup(PwUuid value) {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");
        m_pwLastSelectedGroup = value;
    }

	public PwUuid getLastTopVisibleGroup()
	{
		return m_pwLastTopVisibleGroup;
	}
	public void setLastTopVisibleGroup(PwUuid value) {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");
        m_pwLastTopVisibleGroup = value;
    }

	public boolean isRecycleBinEnabled()
	{
		return m_bUseRecycleBin;
	}
    public void setRecycleBinEnabled(boolean value) {
		m_bUseRecycleBin = value;
    }

	public PwUuid getRecycleBinUuid()
	{
		return m_pwRecycleBin;
	}
    public void setRecycleBinUuid(PwUuid value)
    {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");
        m_pwRecycleBin = value;
    }

	public Date getRecycleBinChanged()
	{
		return m_dtRecycleBinChanged;
	}
    public void setRecycleBinChanged(Date value) {
		m_dtRecycleBinChanged = value;
    }

	/// <summary>
	/// UUID of the group containing template entries. May be
	/// <c>PwUuid.Zero</c>, if no entry templates group has been specified.
	/// </summary>
	public PwUuid getEntryTemplatesGroup()
	{
		return m_pwEntryTemplatesGroup;
	}
    public void setEntryTemplatesGroup(PwUuid value)
    {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");
        m_pwEntryTemplatesGroup = value;
    }

	public Date getEntryTemplatesGroupChanged()
	{
		return m_dtEntryTemplatesChanged;
	}
    public void setEntryTemplatesGroupChanged(Date value) { m_dtEntryTemplatesChanged = value; }

	public int getHistoryMaxItems()
	{
		return m_nHistoryMaxItems;
	}
    public void setHistoryMaxItems(int value) {
		m_nHistoryMaxItems = value;
    }

	public long getHistoryMaxSize()
	{
		return m_lHistoryMaxSize;
	}
    public void setHistoryMaxSize(long value) {
		m_lHistoryMaxSize = value;
    }

	/// <summary>
	/// Custom data container that can be used by plugins to store
	/// own data in KeePass databases.
	/// </summary>
	public StringDictionaryEx getCustomData()
	{
		return m_vCustomData;
	}
    public void setCustomData(StringDictionaryEx value)
    {
        assert value != null;
        if(value == null) throw new IllegalArgumentException("value");
        m_vCustomData = value;
    }

	/// <summary>
	/// Hash value of the primary file on disk (last read or last write).
	/// A call to <c>SaveAs</c> without making the saved file primary will
	/// not change this hash. May be <c>null</c>.
	/// </summary>
	public byte[] getHashOfFileOnDisk()
	{
		return m_pbHashOfFileOnDisk;
	}

	public byte[] getHashOfLastIO()
	{
		return m_pbHashOfLastIO;
	}

	public boolean getUseFileTransactions()
	{
		return m_bUseFileTransactions;
	}
    public void setUseFileTransactions(boolean value) { m_bUseFileTransactions = value; }

	public boolean getUseFileLocks()
	{
		return m_bUseFileLocks;
	}
		public void setUseFileLocks(boolean value) { m_bUseFileLocks = value; }

	private String m_strDetachBins = null;
	/// <summary>
	/// Detach binaries when opening a file. If this isn't <c>null</c>,
	/// all binaries are saved to the specified path and are removed
	/// from the database.
	/// </summary>
	public String getDetachBinaries()
	{
		return m_strDetachBins;
	}
		public void setDetachBinaries(String value) { m_strDetachBins = value; }

	/// <summary>
	/// Localized application name.
	/// </summary>
	public static String getLocalizedAppName()
	{
		return m_strLocalizedAppName;
	}
		public void setLocalizedAppName(String value) { assert value != null;
            m_strLocalizedAppName = value; }

	/// <summary>
	/// Constructs an empty password manager object.
	/// </summary>
	public PwDatabase()
	{
		if(!m_bPrimaryCreated) m_bPrimaryCreated = true;

		Clear();
	}

	private void Clear()
	{
		m_pgRootGroup = null;
		m_vDeletedObjects = new PwObjectList<PwDeletedObject>();

		m_uuidDataCipher = StandardAesEngine.getAesUuid();
		m_caCompression = PwCompressionAlgorithm.GZip;
		m_uKeyEncryptionRounds = PwDefs.DefaultKeyEncryptionRounds;

		m_pwUserKey = null;
		m_memProtConfig = new MemoryProtectionConfig();

		m_vCustomIcons = new ArrayList<PwCustomIcon>();
		m_bUINeedsIconUpdate = true;

		Date dtNow = new Date();

		m_strName = "";
		m_dtNameChanged = dtNow;
		m_strDesc = "";
		m_dtDescChanged = dtNow;
		m_strDefaultUserName = "";
		m_dtDefaultUserChanged = dtNow;
		m_uMntncHistoryDays = 365;
		m_clr = Color.Empty;

		m_dtKeyLastChanged = dtNow;
		m_lKeyChangeRecDays = -1;
		m_lKeyChangeForceDays = -1;

		m_ioSource = new IOConnectionInfo();
		m_bDatabaseOpened = false;
		m_bModified = false;

		m_pwLastSelectedGroup = PwUuid.Zero;
		m_pwLastTopVisibleGroup = PwUuid.Zero;

		m_bUseRecycleBin = true;
		m_pwRecycleBin = PwUuid.Zero;
		m_dtRecycleBinChanged = dtNow;
		m_pwEntryTemplatesGroup = PwUuid.Zero;
		m_dtEntryTemplatesChanged = dtNow;

		m_nHistoryMaxItems = DefaultHistoryMaxItems;
		m_lHistoryMaxSize = DefaultHistoryMaxSize;

		m_vCustomData = new StringDictionaryEx();

		m_pbHashOfFileOnDisk = null;
		m_pbHashOfLastIO = null;

		m_bUseFileTransactions = false;
		m_bUseFileLocks = false;
	}

	/// <summary>
	/// Initialize the class for managing a new database. Previously loaded
	/// data is deleted.
	/// </summary>
	/// <param name="ioConnection">IO connection of the new database.</param>
	/// <param name="pwKey">Key to open the database.</param>
	public void New(IOConnectionInfo ioConnection, CompositeKey pwKey)
	{
		assert ioConnection != null;
		if(ioConnection == null) throw new IllegalArgumentException("ioConnection");
		assert pwKey != null;
		if(pwKey == null) throw new IllegalArgumentException("pwKey");

		Close();

		m_ioSource = ioConnection;
		m_pwUserKey = pwKey;

		m_bDatabaseOpened = true;
		m_bModified = true;

		m_pgRootGroup = new PwGroup(true, true,
			UrlUtil.StripExtension(UrlUtil.GetFileName(ioConnection.getPath())),
			PwIcon.FolderOpen);
		m_pgRootGroup.setExpanded(true);
	}

	/// <summary>
	/// Open a database. The URL may point to any supported data source.
	/// </summary>
	/// <param name="ioSource">IO connection to load the database from.</param>
	/// <param name="pwKey">Key used to open the specified database.</param>
	/// <param name="slLogger">Logger, which gets all status messages.</param>
	public void Open(IOConnectionInfo ioSource, CompositeKey pwKey,
		IStatusLogger slLogger)
	{
		assert ioSource != null;
		if(ioSource == null) throw new IllegalArgumentException("ioSource");
		assert pwKey != null;
		if(pwKey == null) throw new IllegalArgumentException("pwKey");

		Close();

		try
		{
			m_pgRootGroup = new PwGroup(true, true, UrlUtil.StripExtension(
				UrlUtil.GetFileName(ioSource.getPath())), PwIcon.FolderOpen);
			m_pgRootGroup.setExpanded(true);

			m_pwUserKey = pwKey;

			m_bModified = false;

			KdbxFile kdbx = new KdbxFile(this);
			kdbx.setDetachBinaries(m_strDetachBins);

			InputStream s = IOConnection.OpenRead(ioSource);
			kdbx.Load(s, KdbxFormat.Default, slLogger);
			s.close();

			m_pbHashOfLastIO = kdbx.getHashOfFileOnDisk();
			m_pbHashOfFileOnDisk = kdbx.getHashOfFileOnDisk();
			assert m_pbHashOfFileOnDisk != null;

			m_bDatabaseOpened = true;
			m_ioSource = ioSource;
		}
		catch(Exception e)
		{
			Clear();
			throw new RuntimeException(e);
		}
	}

	/// <summary>
	/// Save the currently opened database. The file is written to the location
	/// it has been opened from.
	/// </summary>
	/// <param name="slLogger">Logger that recieves status information.</param>
	public void Save(IStatusLogger slLogger) throws IOException {
		assert !HasDuplicateUuids();

		FileLock fl = null;
		if(m_bUseFileLocks) fl = new FileLock(m_ioSource);
		try
		{
			FileTransactionEx ft = new FileTransactionEx(m_ioSource,
				m_bUseFileTransactions);
			OutputStream s = ft.OpenWrite();

			KdbxFile kdb = new KdbxFile(this);
			kdb.Save(s, null, KdbxFormat.Default, slLogger);

			ft.CommitWrite();

			m_pbHashOfLastIO = kdb.getHashOfFileOnDisk();
			m_pbHashOfFileOnDisk = kdb.getHashOfFileOnDisk();
			assert m_pbHashOfFileOnDisk != null;
		}
		finally { if(fl != null) fl.close(); }

		m_bModified = false;
	}

	/// <summary>
	/// Save the currently opened database to a different location. If
	/// <paramref name="bIsPrimaryNow" /> is <c>true</c>, the specified
	/// location is made the default location for future saves
	/// using <c>SaveDatabase</c>.
	/// </summary>
	/// <param name="ioConnection">New location to serialize the database to.</param>
	/// <param name="bIsPrimaryNow">If <c>true</c>, the new location is made the
	/// standard location for the database. If <c>false</c>, a copy of the currently
	/// opened database is saved to the specified location, but it isn't
	/// made the default location (i.e. no lock files will be moved for
	/// example).</param>
	/// <param name="slLogger">Logger that recieves status information.</param>
	public void SaveAs(IOConnectionInfo ioConnection, boolean bIsPrimaryNow,
		IStatusLogger slLogger)
	{
		assert ioConnection != null;
		if(ioConnection == null) throw new IllegalArgumentException("ioConnection");

		IOConnectionInfo ioCurrent = m_ioSource; // Remember current
		m_ioSource = ioConnection;

		byte[] pbHashCopy = m_pbHashOfFileOnDisk;

		try { this.Save(slLogger); }
		catch(Exception e)
		{
			m_ioSource = ioCurrent; // Restore
			m_pbHashOfFileOnDisk = pbHashCopy;

			m_pbHashOfLastIO = null;
			throw new RuntimeException(e);
		}

		if(!bIsPrimaryNow)
		{
			m_ioSource = ioCurrent; // Restore
			m_pbHashOfFileOnDisk = pbHashCopy;
		}
	}

	/// <summary>
	/// Closes the currently opened database. No confirmation message is shown
	/// before closing. Unsaved changes will be lost.
	/// </summary>
	public void Close()
	{
		Clear();
	}

	public void MergeIn(PwDatabase pdSource, PwMergeMethod mm)
	{
		MergeIn(pdSource, mm, null);
	}

	public void MergeIn(final PwDatabase pdSource, final PwMergeMethod mm,
		final IStatusLogger slStatus)
	{
		if(pdSource == null) throw new IllegalArgumentException("pdSource");

		if(mm == PwMergeMethod.CreateNewUuids)
		{
			pdSource.getRootGroup().setUuid(new PwUuid(true));
			pdSource.getRootGroup().CreateNewItemUuids(true, true, true);
		}

		// PwGroup pgOrgStructure = m_pgRootGroup.CloneStructure();
		// PwGroup pgSrcStructure = pdSource.RootGroup.CloneStructure();
		// Later in case 'if(mm == PwMergeMethod.Synchronize)':
		// PwObjectPoolEx ppOrg = PwObjectPoolEx.FromGroup(pgOrgStructure);
		// PwObjectPoolEx ppSrc = PwObjectPoolEx.FromGroup(pgSrcStructure);

		final PwObjectPool.PwObjectPoolEx ppOrg = PwObjectPool.PwObjectPoolEx.FromGroup(m_pgRootGroup);
		final PwObjectPool.PwObjectPoolEx ppSrc = PwObjectPool.PwObjectPoolEx.FromGroup(pdSource.getRootGroup());
		GroupHandler ghSrc = new GroupHandler() {
        public boolean delegate(PwGroup pg)
		{
			// if(pg == pdSource.m_pgRootGroup) return true;

			// Do not use ppOrg for finding the group, because new groups
			// might have been added (which are not in the pool, and the
			// pool should not be modified)
			PwGroup pgLocal = m_pgRootGroup.FindGroup(pg.getUuid(), true);
			if(pgLocal == null)
			{
				PwGroup pgSourceParent = pg.getParentGroup();
				PwGroup pgLocalContainer;
				if(pgSourceParent == null)
				{
					// pg is the root group of pdSource, and no corresponding
					// local group was found; create the group within the
					// local root group
					assert pg == pdSource.m_pgRootGroup;
					pgLocalContainer = m_pgRootGroup;
				}
				else if(Objects.equal(pgSourceParent, pdSource.m_pgRootGroup))
					pgLocalContainer = m_pgRootGroup;
				else
					pgLocalContainer = m_pgRootGroup.FindGroup(pgSourceParent.getUuid(), true);
				assert pgLocalContainer != null;
				if(pgLocalContainer == null) pgLocalContainer = m_pgRootGroup;

				PwGroup pgNew = new PwGroup(false, false);
				pgNew.setUuid(pg.getUuid());
				pgNew.AssignProperties(pg, false, true);
				// pgLocalContainer.AddGroup(pgNew, true);
				InsertObjectAtBestPos(pgLocalContainer.getGroups(), pgNew, ppSrc);
				pgNew.setParentGroup(pgLocalContainer);
			}
			else // pgLocal != null
			{
				assert mm != PwMergeMethod.CreateNewUuids;

				if(mm == PwMergeMethod.OverwriteExisting)
					pgLocal.AssignProperties(pg, false, false);
				else if((mm == PwMergeMethod.OverwriteIfNewer) ||
					(mm == PwMergeMethod.Synchronize))
				{
					pgLocal.AssignProperties(pg, true, false);
				}
				// else if(mm == PwMergeMethod.KeepExisting) ...
			}

			return ((slStatus != null) ? slStatus.ContinueWork() : true);
		}};

		EntryHandler ehSrc = new EntryHandler() {
        public boolean delegate(PwEntry pe)
		{
			// PwEntry peLocal = m_pgRootGroup.FindEntry(pe.Uuid, true);
			PwEntry peLocal = (PwEntry) ppOrg.GetItemByUuid(pe.getUuid());
			assert(peLocal ==
					m_pgRootGroup.FindEntry(pe.getUuid(), true));

			if(peLocal == null)
			{
				PwGroup pgSourceParent = pe.getParentGroup();
				PwGroup pgLocalContainer;
				if(Objects.equal(pgSourceParent, pdSource.m_pgRootGroup))
					pgLocalContainer = m_pgRootGroup;
				else
					pgLocalContainer = m_pgRootGroup.FindGroup(pgSourceParent.getUuid(), true);
				assert pgLocalContainer != null;
				if(pgLocalContainer == null) pgLocalContainer = m_pgRootGroup;

				PwEntry peNew = new PwEntry(false, false);
				peNew.setUuid(pe.getUuid());

				// pgLocalContainer.AddEntry(peNew, true);
				InsertObjectAtBestPos(pgLocalContainer.getEntries(), peNew, ppSrc);
				peNew.setParentGroup(pgLocalContainer);
			}
			else // peLocal != null
			{
				assert mm != PwMergeMethod.CreateNewUuids;

				final PwCompareOptions.Options cmpOpt = PwCompareOptions.or(PwCompareOptions.IgnoreParentGroup,
					PwCompareOptions.IgnoreLastAccess, PwCompareOptions.IgnoreHistory,
					PwCompareOptions.NullEmptyEquivStd);
				boolean bEquals = peLocal.EqualsEntry(pe, cmpOpt, MemProtCmpMode.None);

				boolean bOrgBackup = !bEquals;
				if(mm != PwMergeMethod.OverwriteExisting)
					bOrgBackup &= (TimeUtil.CompareLastMod(pe, peLocal, true) > 0);
				bOrgBackup &= !pe.HasBackupOfData(peLocal, false, true);
				if(bOrgBackup) peLocal.CreateBackup(null); // Maintain at end

				boolean bSrcBackup = !bEquals && (mm != PwMergeMethod.OverwriteExisting);
				bSrcBackup &= (TimeUtil.CompareLastMod(peLocal, pe, true) > 0);
				bSrcBackup &= !peLocal.HasBackupOfData(pe, false, true);
				if(bSrcBackup) pe.CreateBackup(null); // Maintain at end

				if(mm == PwMergeMethod.OverwriteExisting)
					peLocal.AssignProperties(pe, false, false, false);
				else if((mm == PwMergeMethod.OverwriteIfNewer) ||
					(mm == PwMergeMethod.Synchronize))
				{
					peLocal.AssignProperties(pe, true, false, false);
				}
				// else if(mm == PwMergeMethod.KeepExisting) ...

				MergeEntryHistory(peLocal, pe, mm);
			}

			return ((slStatus != null) ? slStatus.ContinueWork() : true);
		}};

		ghSrc.delegate(pdSource.getRootGroup());
		if(!pdSource.getRootGroup().TraverseTree(TraversalMethod.PreOrder, ghSrc, ehSrc))
			throw new UnsupportedOperationException();

		IStatusLogger slPrevStatus = m_slStatus;
		m_slStatus = slStatus;

		if(mm == PwMergeMethod.Synchronize)
		{
			RelocateGroups(ppOrg, ppSrc);
			RelocateEntries(ppOrg, ppSrc);
			ReorderObjects(m_pgRootGroup, ppOrg, ppSrc);

			// After all relocations and reorderings
			MergeInLocationChanged(m_pgRootGroup, ppOrg, ppSrc);
//			ppOrg = null; // Pools are now invalid, because the location
//			ppSrc = null; // changed times have been merged in

			// Delete *after* relocating, because relocating might
			// empty some groups that are marked for deletion (and
			// objects that weren't relocated yet might prevent the
			// deletion)
			Map<PwUuid, PwDeletedObject> dOrgDel = CreateDeletedObjectsPool();
			MergeInDeletionInfo(pdSource.m_vDeletedObjects, dOrgDel);
			ApplyDeletions(m_pgRootGroup, dOrgDel);

			// The list and the dictionary should be kept in sync
			assert(m_vDeletedObjects.getUCount() == dOrgDel.size());
		}

		// Must be called *after* merging groups, because group UUIDs
		// are required for recycle bin and entry template UUIDs
		MergeInDbProperties(pdSource, mm);

		MergeInCustomIcons(pdSource);

		MaintainBackups();

		assert(!HasDuplicateUuids());
		m_slStatus = slPrevStatus;
	}

	private void MergeInCustomIcons(PwDatabase pdSource)
	{
		for (PwCustomIcon pwci : pdSource.getCustomIcons())
		{
			if(GetCustomIconIndex(pwci.getUuid()) >= 0) continue;

			m_vCustomIcons.add(pwci); // PwCustomIcon is immutable
			m_bUINeedsIconUpdate = true;
		}
	}

	private Map<PwUuid, PwDeletedObject> CreateDeletedObjectsPool() {
		Map<PwUuid, PwDeletedObject> d =
				new HashMap<PwUuid, PwDeletedObject>();


		int n = (int) m_vDeletedObjects.getUCount();
		for (int i = n - 1; i >= 0; --i) {
			PwDeletedObject pdo = m_vDeletedObjects.GetAt(i);

			PwDeletedObject pdoEx;
			if ((pdoEx = d.get(pdo.getUuid())) != null) {
				assert (false); // Found duplicate, which should not happen

				if (pdo.getDeletionTime().getTime() > pdoEx.getDeletionTime().getTime())
					pdoEx.setDeletionTime(pdo.getDeletionTime());

				m_vDeletedObjects.RemoveAt(i);
			} else d.put(pdo.getUuid(), pdo);

		}
		return d;
	}

	private void MergeInDeletionInfo(PwObjectList<PwDeletedObject> lSrc,
									 Map<PwUuid, PwDeletedObject> dOrgDel)
	{
		for(PwDeletedObject pdoSrc : lSrc)
		{
			PwDeletedObject pdoOrg;
			if((pdoOrg = dOrgDel.get(pdoSrc.getUuid())) != null) // Update
			{
				assert(pdoOrg.getUuid().Equals(pdoSrc.getUuid()));
				if(pdoSrc.getDeletionTime().getTime() > pdoOrg.getDeletionTime().getTime())
					pdoOrg.setDeletionTime(pdoSrc.getDeletionTime());
			}
			else // Add
			{
				m_vDeletedObjects.Add(pdoSrc);
				dOrgDel.put(pdoSrc.getUuid(), pdoSrc);
			}
		}
	}

	private <T extends IDeepCloneable<T> & IStructureItem> void ApplyDeletions(PwObjectList<T> l, Predicate<T> fCanDelete,
																			   Map<PwUuid, PwDeletedObject> dOrgDel)
	{
		int n = l.getUCount();
		for(int i = n - 1; i >= 0; --i)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			T t = l.GetAt(i);

			PwDeletedObject pdo;
			if((pdo = dOrgDel.get(t.getUuid())) != null)
			{
				assert(t.getUuid().Equals(pdo.getUuid()));

				boolean bDel = (TimeUtil.Compare(t.getLastModificationTime(),
						pdo.getDeletionTime(), true) < 0);
				bDel &= fCanDelete.apply(t);

				if(bDel) l.RemoveAt(i);
				else
				{

					// Prevent future deletion attempts; this also prevents
					// delayed deletions (emptying a group could cause a
					// group to be deleted, if the deletion was prevented
					// before due to the group not being empty)
					if(!m_vDeletedObjects.Remove(pdo)) { assert(false); }
					if(dOrgDel.remove(pdo.getUuid()) == null) { assert(false); }
				}
			}
		}
	}
	final static Predicate<PwGroup> SafeCanDeleteGroup = new Predicate<PwGroup>() { public boolean apply(PwGroup pg) {
	{
		if(pg == null) { assert(false); return false; }

		if(pg.getGroups().getUCount() > 0) return false;
		if(pg.getEntries().getUCount() > 0) return false;
		return true;
	}}};

	final static Predicate<PwEntry> SafeCanDeleteEntry = new Predicate<PwEntry>() { public boolean apply(PwEntry pe) {
	{
		if(pe == null) { assert(false); return false; }

		return true;
	}}};

	// Apply deletions on all objects in the specified container
	// (but not the container itself), using post-order traversal
	// to avoid implicit deletions;
	// https://sourceforge.net/p/keepass/bugs/1499/
	private void ApplyDeletions(PwGroup pgContainer,
								Map<PwUuid, PwDeletedObject> dOrgDel)
	{
		for(PwGroup pg : pgContainer.getGroups()) // Post-order traversal
		{
			ApplyDeletions(pg, dOrgDel);
		}
		ApplyDeletions(pgContainer.getGroups(), PwDatabase.SafeCanDeleteGroup, dOrgDel);
		ApplyDeletions(pgContainer.getEntries(), PwDatabase.SafeCanDeleteEntry, dOrgDel);
	}

	private void RelocateGroups(PwObjectPool.PwObjectPoolEx ppOrg, PwObjectPool.PwObjectPoolEx ppSrc)
	{
		PwObjectList<PwGroup> vGroups = m_pgRootGroup.GetGroups(true);

		for(PwGroup pg : vGroups)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			// PwGroup pgOrg = pgOrgStructure.FindGroup(pg.Uuid, true);
			IStructureItem ptOrg = ppOrg.GetItemByUuid(pg.getUuid());
			if(ptOrg == null) continue;
			// PwGroup pgSrc = pgSrcStructure.FindGroup(pg.Uuid, true);
			IStructureItem ptSrc = ppSrc.GetItemByUuid(pg.getUuid());
			if(ptSrc == null) continue;

			PwGroup pgOrgParent = ptOrg.getParentGroup();
			// vGroups does not contain the root group, thus pgOrgParent
			// should not be null
			if(pgOrgParent == null) { assert false; continue; }

			PwGroup pgSrcParent = ptSrc.getParentGroup();
			// pgSrcParent may be null (for the source root group)
			if(pgSrcParent == null) continue;

			if(pgOrgParent.getUuid().Equals(pgSrcParent.getUuid()))
			{
//				pg.setLocationChanged((ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime()) ?
//					ptSrc.getLocationChanged() : ptOrg.getLocationChanged());
				continue;
			}

			if(ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime())
			{
				PwGroup pgLocal = m_pgRootGroup.FindGroup(pgSrcParent.getUuid(), true);
				if(pgLocal == null) { assert false; continue; }

				if(pgLocal.IsContainedIn(pg)) continue;

				pg.getParentGroup().getGroups().Remove(pg);

				// pgLocal.AddGroup(pg, true);
				InsertObjectAtBestPos(pgLocal.getGroups(), pg, ppSrc);
				pg.setParentGroup(pgLocal);

				// pg.LocationChanged = ptSrc.LocationChanged;
			}
			else
			{
				assert pg.getParentGroup().getUuid().Equals(pgOrgParent.getUuid());
				assert pg.getLocationChanged().equals(ptOrg.getLocationChanged());
			}
		}

		assert m_pgRootGroup.GetGroups(true).getUCount() == vGroups.getUCount();
	}

	private void RelocateEntries(PwObjectPool.PwObjectPoolEx ppOrg, PwObjectPool.PwObjectPoolEx ppSrc)
	{
		PwObjectList<PwEntry> vEntries = m_pgRootGroup.GetEntries(true);

		for(PwEntry pe : vEntries)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			// PwEntry peOrg = pgOrgStructure.FindEntry(pe.Uuid, true);
			IStructureItem ptOrg = ppOrg.GetItemByUuid(pe.getUuid());
			if(ptOrg == null) continue;
			// PwEntry peSrc = pgSrcStructure.FindEntry(pe.Uuid, true);
			IStructureItem ptSrc = ppSrc.GetItemByUuid(pe.getUuid());
			if(ptSrc == null) continue;

			PwGroup pgOrg = ptOrg.getParentGroup();
			PwGroup pgSrc = ptSrc.getParentGroup();
			if(pgOrg.getUuid().Equals(pgSrc.getUuid()))
			{
//				pe.setLocationChanged((ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime()) ?
//					ptSrc.getLocationChanged() : ptOrg.getLocationChanged());
				continue;
			}

			if(ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime())
			{
				PwGroup pgLocal = m_pgRootGroup.FindGroup(pgSrc.getUuid(), true);
				if(pgLocal == null) { assert false; continue; }

				pe.getParentGroup().getEntries().Remove(pe);

				// pgLocal.AddEntry(pe, true);
				InsertObjectAtBestPos(pgLocal.getEntries(), pe, ppSrc);
				pe.setParentGroup(pgLocal);

				// pe.LocationChanged = ptSrc.LocationChanged;
			}
			else
			{
				assert pe.getParentGroup().getUuid().Equals(pgOrg.getUuid());
				assert pe.getLocationChanged() == ptOrg.getLocationChanged();
			}
		}

		assert m_pgRootGroup.GetEntries(true).getUCount() == vEntries.getUCount();
	}

	private void ReorderObjects(PwGroup pg, PwObjectPool.PwObjectPoolEx ppOrg,
								PwObjectPool.PwObjectPoolEx ppSrc)
	{
		ReorderObjectList(pg.getGroups(), ppOrg, ppSrc);
		ReorderObjectList(pg.getEntries(), ppOrg, ppSrc);

		for (PwGroup pgSub : pg.getGroups()) {
			ReorderObjects(pgSub, ppOrg, ppSrc);
		}
	}
	static class Pair<F,S> {
		public final F fst;
		public final S snd;
		public Pair(F first, S second) {
		    fst = first; snd = second;
		}
	}
	private <T extends IDeepCloneable<T> & IStructureItem> void ReorderObjectList(PwObjectList<T> lItems,
	PwObjectPool.PwObjectPoolEx ppOrg, PwObjectPool.PwObjectPoolEx ppSrc)
	{

		List<PwObjectPool.PwObjectBlock<T>> lBlocks = PartitionConsec(lItems, ppOrg, ppSrc);
		if(lBlocks.size() <= 1) return;
		PwObjectList<T> lOrgItems = lItems.CloneShallow();


		Queue<Pair<Integer, Integer>> qToDo = new LinkedList<Pair<Integer, Integer>>();
		qToDo.add(new Pair<>(0, lBlocks.size() - 1));

		while(qToDo.size() > 0)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			Pair<Integer, Integer> kvp = qToDo.poll();
			if(kvp.snd <= kvp.fst) { assert false; continue; }

			PwObjectPool.PwObjectPoolEx[] pPool = new PwObjectPool.PwObjectPoolEx[1];
			int iPivot = FindLocationChangedPivot(lBlocks, kvp, pPool);
			PwObjectPool.PwObjectBlock<T> bPivot = lBlocks.get(iPivot);

			T tPivotPrimary = bPivot.getPrimaryItem();
			if(tPivotPrimary == null) { assert(false); continue; }
			long idPivot = pPool[0].GetIdByUuid(tPivotPrimary.getUuid());
			if(idPivot == 0) { assert(false); continue; }

			Queue<PwObjectPool.PwObjectBlock<T>> qBefore = new LinkedList<PwObjectPool.PwObjectBlock<T>>();
			Queue<PwObjectPool.PwObjectBlock<T>> qAfter = new LinkedList<PwObjectPool.PwObjectBlock<T>>();
			boolean bBefore = true;

			for(int i = kvp.fst; i <= kvp.snd; ++i)
			{
				if(i == iPivot) { bBefore = false; continue; }

				PwObjectPool.PwObjectBlock<T> b = lBlocks.get(i);
				assert(b.getLocationChanged().getTime() <= bPivot.getLocationChanged().getTime());

				T t = b.getPrimaryItem();
				if(t != null)
				{
					long idBPri = pPool[0].GetIdByUuid(t.getUuid());
					if(idBPri > 0)
					{
						if(idBPri < idPivot) qBefore.add(b);
						else qAfter.add(b);

						continue;
					}
				}
				else { assert(false); }

				if(bBefore) qBefore.add(b);
				else qAfter.add(b);
			}

				int j = kvp.fst;
				while(qBefore.size() > 0) { lBlocks.set(j, qBefore.poll()); ++j; }
				int iNewPivot = j;
				lBlocks.set(j, bPivot);
				++j;
				while(qAfter.size() > 0) { lBlocks.set(j, qAfter.poll()); ++j; }
				assert(j == (kvp.snd + 1));

				if((iNewPivot - 1) > kvp.fst)
					qToDo.add(new Pair<Integer, Integer>(kvp.fst, iNewPivot - 1));
				if((iNewPivot + 1) < kvp.snd)
					qToDo.add(new Pair<Integer, Integer>(iNewPivot + 1, kvp.snd));
			}

			int u = 0;
		for (PwObjectPool.PwObjectBlock<T> b : lBlocks)
		{
			for (T t : b)
			{
			    lItems.SetAt(u, t);
				++u;
			}

		}
		assert(u == lItems.getUCount());

if (false) { // debug
	    assert(u == lOrgItems.getUCount());
		for(T ptItem : lOrgItems)
		{
			assert lItems.IndexOf(ptItem) >= 0;
		}
}
	}

	private static <T extends IDeepCloneable<T> & IStructureItem> List<PwObjectPool.PwObjectBlock<T>> PartitionConsec(PwObjectList<T> lItems,
																													  PwObjectPool.PwObjectPoolEx ppOrg, PwObjectPool.PwObjectPoolEx ppSrc)
	{
		List<PwObjectPool.PwObjectBlock<T>> lBlocks = new ArrayList<PwObjectPool.PwObjectBlock<T>>();

		Map<PwUuid, Boolean> dItemUuids = new HashMap<PwUuid, Boolean>();
		for(T t : lItems) { dItemUuids.put(t.getUuid(), true); }

		int n = lItems.getUCount();
		for(int u = 0; u < n; ++u)
		{
			T t = lItems.GetAt(u);
			PwObjectPool.PwObjectBlock<T> b = new PwObjectPool.PwObjectBlock<T>();

			Date[] dtLoc = new Date[1];
			PwObjectPool.PwObjectPoolEx pPool = GetBestPool(t, ppOrg, ppSrc, dtLoc);
			b.Add(t, dtLoc[0], pPool);

			lBlocks.add(b);

			long idOrg = ppOrg.GetIdByUuid(t.getUuid());
			long idSrc = ppSrc.GetIdByUuid(t.getUuid());
			if((idOrg == 0) || (idSrc == 0)) continue;

			for(int x = u + 1; x < n; ++x)
			{
			    T tNext = lItems.GetAt(x);

				long idOrgNext = idOrg + 1;
				while (true)
				{
					IStructureItem ptOrg = ppOrg.GetItemById(idOrgNext);
					if(ptOrg == null) { idOrgNext = 0; break; }
					if(ptOrg.getUuid().Equals(tNext.getUuid())) break; // Found it
					if(dItemUuids.containsKey(ptOrg.getUuid())) { idOrgNext = 0; break; }
					++idOrgNext;
				}
				if (idOrgNext == 0) break;

                long idSrcNext = idSrc + 1;
				while (true)
				{
					IStructureItem ptSrc = ppSrc.GetItemById(idSrcNext);
					if(ptSrc == null) { idSrcNext = 0; break; }
					if(ptSrc.getUuid().Equals(tNext.getUuid())) break; // Found it
					if(dItemUuids.containsKey(ptSrc.getUuid())) { idSrcNext = 0; break; }
					++idSrcNext;
				}
				if (idSrcNext == 0) break;

				pPool = GetBestPool(tNext, ppOrg, ppSrc, dtLoc);
				b.Add(tNext, dtLoc[0], pPool);

				++u;
				idOrg = idOrgNext;
				idSrc = idSrcNext;
			}
		}

		return lBlocks;
	}

	private static <T extends IDeepCloneable<T> & IStructureItem> PwObjectPool.PwObjectPoolEx GetBestPool(T t, PwObjectPool.PwObjectPoolEx ppOrg,
	PwObjectPool.PwObjectPoolEx ppSrc, Date[] dtLoc)
	{
		PwObjectPool.PwObjectPoolEx p = null;
		dtLoc[0] = new Date(0);

		IStructureItem ptOrg = ppOrg.GetItemByUuid(t.getUuid());
		if(ptOrg != null)
		{
			dtLoc[0] = ptOrg.getLocationChanged();
			p = ppOrg;
		}

		IStructureItem ptSrc = ppSrc.GetItemByUuid(t.getUuid());
		if((ptSrc != null) && (ptSrc.getLocationChanged().getTime() > dtLoc[0].getTime()))
		{
			dtLoc[0] = ptSrc.getLocationChanged();
			p = ppSrc;
		}

		assert(p != null);
		return p;
	}

	private static <T extends IDeepCloneable<T> & IStructureItem> int FindLocationChangedPivot(List<PwObjectPool.PwObjectBlock<T>> lBlocks,
																							   Pair<Integer, Integer> kvpRange, PwObjectPool.PwObjectPoolEx[] pPool)
	{
		pPool[0] = null;

		int iPosMax = kvpRange.fst;
		Date dtMax = new Date(0);

		for(int i = kvpRange.fst; i <= kvpRange.snd; ++i)
		{
			PwObjectPool.PwObjectBlock < T > b = lBlocks.get(i);
			if (b.getLocationChanged().getTime() > dtMax.getTime())
			{
				iPosMax = i;
				dtMax = b.getLocationChanged();
				pPool[0] = b.getPoolAssoc();
			}
		}

		return iPosMax;
	}




	private static void MergeInLocationChanged(PwGroup pg,
											   final PwObjectPool.PwObjectPoolEx ppOrg, final PwObjectPool.PwObjectPoolEx ppSrc)
	{
			GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pgSub)
			{
				Date[] dt = new Date[1];
				if(GetBestPool(pgSub, ppOrg, ppSrc, dt) != null)
					pgSub.setLocationChanged(dt[0]);
				else { assert(false); }
				return true;
			}};

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				Date[] dt = new Date[1];
				if(GetBestPool(pe, ppOrg, ppSrc, dt) != null)
					pe.setLocationChanged(dt[0]);
				else { assert(false); }
				return true;
			}};

			gh.delegate(pg);
			pg.TraverseTree(TraversalMethod.PreOrder, gh, eh);
		}

		private static <T extends IDeepCloneable<T> & IStructureItem> void InsertObjectAtBestPos(PwObjectList<T> lItems,
			T tNew, PwObjectPool.PwObjectPoolEx ppSrc)
		{
			if(tNew == null) { assert(false); return; }

			long idSrc = ppSrc.GetIdByUuid(tNew.getUuid());
			if(idSrc == 0) { assert(false); lItems.Add(tNew); return; }

			final int uIdOffset = 2;
			Map<PwUuid, Integer> dOrg = new HashMap<PwUuid, Integer>();
			for(int u = 0; u < lItems.getUCount(); ++u)
				dOrg.put(lItems.GetAt(u).getUuid(), uIdOffset + u);

			long idSrcNext = idSrc + 1;
			Integer idOrgNext = 0;
			while(true)
			{
				IStructureItem pNext = ppSrc.GetItemById(idSrcNext);
				if(pNext == null) break;
				if((idOrgNext = dOrg.get(pNext.getUuid())) != null) break;
				++idSrcNext;
			}

			if(idOrgNext != 0)
			{
				lItems.Insert(idOrgNext - uIdOffset, tNew);
				return;
			}

			long idSrcPrev = idSrc - 1;
			Integer idOrgPrev = 0;
			while(true)
			{
				IStructureItem pPrev = ppSrc.GetItemById(idSrcPrev);
				if(pPrev == null) break;
				if((idOrgPrev = dOrg.get(pPrev.getUuid())) != null) break;
				--idSrcPrev;
			}

			if(idOrgPrev != 0)
			{
				lItems.Insert(idOrgPrev + 1 - uIdOffset, tNew);
				return;
	///////////////////////////////
		}

		lItems.Add(tNew);
	}

	private void MergeInDbProperties(PwDatabase pdSource, PwMergeMethod mm)
	{
		if(pdSource == null) { assert false; return; }
		if((mm == PwMergeMethod.KeepExisting) || (mm == PwMergeMethod.None))
			return;

		boolean bForce = (mm == PwMergeMethod.OverwriteExisting);

		if(bForce || (pdSource.m_dtNameChanged.getTime() > m_dtNameChanged.getTime()))
		{
			m_strName = pdSource.m_strName;
			m_dtNameChanged = pdSource.m_dtNameChanged;
		}

		if(bForce || (pdSource.m_dtDescChanged.getTime() > m_dtDescChanged.getTime()))
		{
			m_strDesc = pdSource.m_strDesc;
			m_dtDescChanged = pdSource.m_dtDescChanged;
		}

		if(bForce || (pdSource.m_dtDefaultUserChanged.getTime() > m_dtDefaultUserChanged.getTime()))
		{
			m_strDefaultUserName = pdSource.m_strDefaultUserName;
			m_dtDefaultUserChanged = pdSource.m_dtDefaultUserChanged;
		}

		if(bForce) m_clr = pdSource.m_clr;

		PwUuid pwPrefBin = m_pwRecycleBin, pwAltBin = pdSource.m_pwRecycleBin;
		if(bForce || (pdSource.m_dtRecycleBinChanged.getTime() > m_dtRecycleBinChanged.getTime()))
		{
			pwPrefBin = pdSource.m_pwRecycleBin;
			pwAltBin = m_pwRecycleBin;
			m_bUseRecycleBin = pdSource.m_bUseRecycleBin;
			m_dtRecycleBinChanged = pdSource.m_dtRecycleBinChanged;
		}
		if(m_pgRootGroup.FindGroup(pwPrefBin, true) != null)
			m_pwRecycleBin = pwPrefBin;
		else if(m_pgRootGroup.FindGroup(pwAltBin, true) != null)
			m_pwRecycleBin = pwAltBin;
		else m_pwRecycleBin = PwUuid.Zero; // assert false;

		PwUuid pwPrefTmp = m_pwEntryTemplatesGroup, pwAltTmp = pdSource.m_pwEntryTemplatesGroup;
		if(bForce || (pdSource.m_dtEntryTemplatesChanged.getTime() > m_dtEntryTemplatesChanged.getTime()))
		{
			pwPrefTmp = pdSource.m_pwEntryTemplatesGroup;
			pwAltTmp = m_pwEntryTemplatesGroup;
			m_dtEntryTemplatesChanged = pdSource.m_dtEntryTemplatesChanged;
		}
		if(m_pgRootGroup.FindGroup(pwPrefTmp, true) != null)
			m_pwEntryTemplatesGroup = pwPrefTmp;
		else if(m_pgRootGroup.FindGroup(pwAltTmp, true) != null)
			m_pwEntryTemplatesGroup = pwAltTmp;
		else m_pwEntryTemplatesGroup = PwUuid.Zero; // assert false;
	}

	private void MergeEntryHistory(PwEntry pe, PwEntry peSource,
		PwMergeMethod mm)
	{
		if(!pe.getUuid().Equals(peSource.getUuid())) { assert false; return; }

		if(pe.getHistory().getUCount() == peSource.getHistory().getUCount())
		{
			boolean bEqual = true;
			for(int uEnum = 0; uEnum < pe.getHistory().getUCount(); ++uEnum)
			{
				if(!Objects.equal(pe.getHistory().GetAt(uEnum).getLastModificationTime().getTime(),
					peSource.getHistory().GetAt(uEnum).getLastModificationTime().getTime()))
				{
					bEqual = false;
					break;
				}
			}

			if(bEqual) return;
		}

		if((m_slStatus != null) && !m_slStatus.ContinueWork()) return;

		Map<Date, PwEntry> dict = new TreeMap<Date, PwEntry>();
		for(PwEntry peOrg : pe.getHistory())
		{
			dict.put(peOrg.getLastModificationTime(), peOrg);
		}

		for(PwEntry peSrc : peSource.getHistory())
		{
			Date dt = peSrc.getLastModificationTime();
			if(dict.containsKey(dt))
			{
				if(mm == PwMergeMethod.OverwriteExisting)
					dict.put(dt, peSrc.CloneDeep());
			}
			else dict.put(dt, peSrc.CloneDeep());
		}

		pe.getHistory().Clear();
		for(Map.Entry<Date, PwEntry> kvpCur : dict.entrySet())
		{
			assert kvpCur.getValue().getUuid().Equals(pe.getUuid());
			assert kvpCur.getValue().getHistory().getUCount() == 0;
			pe.getHistory().Add(kvpCur.getValue());
		}
	}

	public boolean MaintainBackups()
	{
		if(m_pgRootGroup == null) { assert false; return false; }

		final boolean[] bDeleted = { false };
		EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
		{
			if(pe.MaintainBackups(PwDatabase.this)) bDeleted[0] = true;
			return true;
		}};

		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, null, eh);
		return bDeleted[0];
	}

	/* /// <summary>
	/// Synchronize current database with another one.
	/// </summary>
	/// <param name="strFile">Source file.</param>
	public void Synchronize(string strFile)
	{
		PwDatabase pdSource = new PwDatabase();

		IOConnectionInfo ioc = IOConnectionInfo.FromPath(strFile);
		pdSource.Open(ioc, m_pwUserKey, null);

		MergeIn(pdSource, PwMergeMethod.Synchronize);
	} */

	/// <summary>
	/// Get the index of a custom icon.
	/// </summary>
	/// <param name="pwIconId">ID of the icon.</param>
	/// <returns>Index of the icon.</returns>
	public int GetCustomIconIndex(PwUuid pwIconId)
	{
		for(int i = 0; i < m_vCustomIcons.size(); ++i)
		{
			PwCustomIcon pwci = m_vCustomIcons.get(i);
			if(pwci.getUuid().Equals(pwIconId))
				return i;
		}

		// assert false; // Do not assert
		return -1;
	}

	public int GetCustomIconIndex(byte[] pbPngData)
	{
		if(pbPngData == null) { assert false; return -1; }

		for(int i = 0; i < m_vCustomIcons.size(); ++i)
		{
			PwCustomIcon pwci = m_vCustomIcons.get(i);
			byte[] pbEx = pwci.getImageDataPng();
			if(pbEx == null) { assert false; continue; }

			if(MemUtil.ArraysEqual(pbEx, pbPngData))
				return i;
		}

		return -1;
	}

	/// <summary>
	/// Get a custom icon. This function can return <c>null</c>, if
	/// no cached image of the icon is available.
	/// </summary>
	/// <param name="pwIconId">ID of the icon.</param>
	/// <returns>Image data.</returns>
	public byte[] GetCustomIcon(PwUuid pwIconId)
	{
		int nIndex = GetCustomIconIndex(pwIconId);

		if(nIndex >= 0) return m_vCustomIcons.get(nIndex).getImageDataPng();
		else { assert false; return null; }
	}

	public boolean DeleteCustomIcons(final List<PwUuid> vUuidsToDelete)
	{
		assert vUuidsToDelete != null;
		if(vUuidsToDelete == null) throw new IllegalArgumentException("vUuidsToDelete");
		if(vUuidsToDelete.size() <= 0) return true;

		GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			PwUuid uuidThis = pg.getCustomIconUuid();
			if(uuidThis.Equals(PwUuid.Zero)) return true;

			for(PwUuid uuidDelete : vUuidsToDelete)
			{
				if(uuidThis.Equals(uuidDelete))
				{
					pg.setCustomIconUuid(PwUuid.Zero);
					break;
				}
			}

			return true;
		}};

		EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
		{
			RemoveCustomIconUuid(pe, vUuidsToDelete);
			return true;
		}};

		gh.delegate(m_pgRootGroup);
		if(!m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, eh))
		{
			assert false;
			return false;
		}

		for(PwUuid pwUuid : vUuidsToDelete)
		{
			int nIndex = GetCustomIconIndex(pwUuid);
			if(nIndex >= 0) m_vCustomIcons.remove(nIndex);
		}

		return true;
	}

	private static void RemoveCustomIconUuid(PwEntry pe, List<PwUuid> vToDelete)
	{
		PwUuid uuidThis = pe.getCustomIconUuid();
		if(uuidThis.Equals(PwUuid.Zero)) return;

		for(PwUuid uuidDelete : vToDelete)
		{
			if(uuidThis.Equals(uuidDelete))
			{
				pe.setCustomIconUuid(PwUuid.Zero);
				break;
			}
		}

		for(PwEntry peHistory : pe.getHistory())
			RemoveCustomIconUuid(peHistory, vToDelete);
	}

	private int GetTotalObjectUuidCount()
	{
		int[] uGroups = new int[1], uEntries = new int[1];
		m_pgRootGroup.GetCounts(true, uGroups, uEntries);
		long uTotal = uGroups[0] + uEntries[0] + 1l; // 1 for root group
		if(uTotal > 0x7FFFFFFF) { assert(false); return 0x7FFFFFFF; }
		return (int)uTotal;
	}
	private boolean HasDuplicateUuids()
	{
		int nTotal = GetTotalObjectUuidCount();
		final HashMap<PwUuid, Object> d = new HashMap<PwUuid, Object>(nTotal);
		final boolean[] bDupFound = { false };

		GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			PwUuid pu = pg.getUuid();
			if(d.containsKey(pu))
			{
				bDupFound[0] = true;
				return false;
			}

			d.put(pu, null);
			assert(d.containsKey(pu));
			return true;
		}};

		EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
		{
			PwUuid pu = pe.getUuid();
			if(d.containsKey(pu))
			{
				bDupFound[0] = true;
				return false;
			}

			d.put(pu, null);
			assert(d.containsKey(pu));
			return true;
		}};
		gh.delegate(m_pgRootGroup);

		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, eh);
		assert(bDupFound[0] || (d.size() == nTotal));
		return bDupFound[0];
	}

	private void FixDuplicateUuids() {
		int nTotal = GetTotalObjectUuidCount();
		final HashMap<PwUuid, Object> d = new HashMap<PwUuid, Object>(nTotal);

		GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			PwUuid pu = pg.getUuid();
			if (d.containsKey(pu)) {
				pu = new PwUuid(true);
				while (d.containsKey(pu)) {
					assert(false);
					pu = new PwUuid(true);
				}

				pg.setUuid(pu);
			}

			d.put(pu, null);
			return true;
		}} ;

		EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
		{
			PwUuid pu = pe.getUuid();
			if (d.containsKey(pu)) {
				pu = new PwUuid(true);
				while (d.containsKey(pu)) {
					assert(false);
					pu = new PwUuid(true);
				}

				pe.SetUuid(pu, true);
			}

			d.put(pu, null);
			return true;
		}};

		gh.delegate(m_pgRootGroup);
		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, eh);

		assert d.size() == nTotal;
		assert !HasDuplicateUuids();
	}

	/* public void CreateBackupFile(IStatusLogger sl)
	{
		if(sl != null) sl.SetText(KLRes.CreatingBackupFile, LogStatusType.Info);

		IOConnectionInfo iocBk = m_ioSource.CloneDeep();
		iocBk.Path += StrBackupExtension;

		bool bMadeUnhidden = UrlUtil.UnhideFile(iocBk.Path);

		bool bFastCopySuccess = false;
		if(m_ioSource.IsLocalFile() && (m_ioSource.UserName.Length == 0) &&
			(m_ioSource.Password.Length == 0))
		{
			try
			{
				string strFile = m_ioSource.Path + StrBackupExtension;
				File.Copy(m_ioSource.Path, strFile, true);
				bFastCopySuccess = true;
			}
			catch(Exception) { assert false; }
		}

		if(bFastCopySuccess == false)
		{
			using(Stream sIn = IOConnection.OpenRead(m_ioSource))
			{
				using(Stream sOut = IOConnection.OpenWrite(iocBk))
				{
					MemUtil.CopyStream(sIn, sOut);
					sOut.Close();
				}

				sIn.Close();
			}
		}

		if(bMadeUnhidden) UrlUtil.HideFile(iocBk.Path, true); // Hide again
	} */

	/* private static void RemoveData(PwGroup pg)
	{
		EntryHandler eh = delegate(PwEntry pe)
		{
			pe.AutoType.Clear();
			pe.Binaries.Clear();
			pe.History.Clear();
			pe.Strings.Clear();
			return true;
		};

		pg.TraverseTree(TraversalMethod.PreOrder, null, eh);
	} */

	public int DeleteDuplicateEntries(IStatusLogger sl)
	{
		int uDeleted = 0;

		PwGroup pgRecycleBin = null;
		if(m_bUseRecycleBin)
			pgRecycleBin = m_pgRootGroup.FindGroup(m_pwRecycleBin, true);

		Date dtNow = new Date();
		PwObjectList<PwEntry> l = m_pgRootGroup.GetEntries(true);
		int i = 0;
		while(true)
		{
			if(i >= ((int)l.getUCount() - 1)) break;

			if(sl != null)
			{
				long lCnt = (long)l.getUCount(), li = (long)i;
				long nArTotal = (lCnt * lCnt) / 2L;
				long nArCur = li * lCnt - ((li * li) / 2L);
				long nArPct = (nArCur * 100L) / nArTotal;
				if(nArPct < 0) nArPct = 0;
				if(nArPct > 100) nArPct = 100;
				if(!sl.SetProgress((int)nArPct)) break;
			}

			PwEntry peA = l.GetAt((int)i);

			for(int j = (int)i + 1; j < l.getUCount(); ++j)
			{
				PwEntry peB = l.GetAt(j);
				if(!DupEntriesEqual(peA, peB)) continue;

				boolean bDeleteA = (TimeUtil.CompareLastMod(peA, peB, true) <= 0);
				if(pgRecycleBin != null)
				{
					boolean bAInBin = peA.IsContainedIn(pgRecycleBin);
					boolean bBInBin = peB.IsContainedIn(pgRecycleBin);

					if(bAInBin && !bBInBin) bDeleteA = true;
					else if(bBInBin && !bAInBin) bDeleteA = false;
				}

				if(bDeleteA)
				{
					peA.getParentGroup().getEntries().Remove(peA);
					m_vDeletedObjects.Add(new PwDeletedObject(peA.getUuid(), dtNow));

					l.RemoveAt((int)i);
					--i;
				}
				else
				{
					peB.getParentGroup().getEntries().Remove(peB);
					m_vDeletedObjects.Add(new PwDeletedObject(peB.getUuid(), dtNow));

					l.RemoveAt(j);
				}

				++uDeleted;
				break;
			}

			++i;
		}

		return uDeleted;
	}

	private static List<String> m_lStdFields = null;
	private static boolean DupEntriesEqual(PwEntry a, PwEntry b)
	{
		if(m_lStdFields == null) m_lStdFields = PwDefs.GetStandardFields();

		for(String strStdKey : m_lStdFields)
		{
			String strA = a.getStrings().ReadSafe(strStdKey);
			String strB = b.getStrings().ReadSafe(strStdKey);
			if(!strA.equals(strB)) return false;
		}

		for(Map.Entry<String, ProtectedString> kvpA : a.getStrings())
		{
			if(PwDefs.IsStandardField(kvpA.getKey())) continue;

			ProtectedString psB = b.getStrings().Get(kvpA.getKey());
			if(psB == null) return false;

			// Ignore protection setting, compare values only
			if(!kvpA.getValue().ReadString().equals(psB.ReadString())) return false;
		}

		for(Map.Entry<String, ProtectedString> kvpB : b.getStrings())
		{
			if(PwDefs.IsStandardField(kvpB.getKey())) continue;

			ProtectedString psA = a.getStrings().Get(kvpB.getKey());
			if(psA == null) return false;

			// Must be equal by logic
			assert kvpB.getValue().ReadString().equals(psA.ReadString());
		}

		if(a.getBinaries().getUCount() != b.getBinaries().getUCount()) return false;
		for(Map.Entry<String, ProtectedBinary> kvpBin : a.getBinaries())
		{
			ProtectedBinary pbB = b.getBinaries().Get(kvpBin.getKey());
			if(pbB == null) return false;

			// Ignore protection setting, compare values only
			byte[] pbDataA = kvpBin.getValue().ReadData();
			byte[] pbDataB = pbB.ReadData();
			boolean bBinEq = MemUtil.ArraysEqual(pbDataA, pbDataB);
			MemUtil.ZeroByteArray(pbDataA);
			MemUtil.ZeroByteArray(pbDataB);
			if(!bBinEq) return false;
		}

		return true;
	}

	public int DeleteEmptyGroups()
	{
		int uDeleted = 0;

		PwObjectList<PwGroup> l = m_pgRootGroup.GetGroups(true);
		int iStart = (int)l.getUCount() - 1;
		for(int i = iStart; i >= 0; --i)
		{
			PwGroup pg = l.GetAt((int)i);
			if((pg.getGroups().getUCount() > 0) || (pg.getEntries().getUCount() > 0)) continue;

			pg.getParentGroup().getGroups().Remove(pg);
			m_vDeletedObjects.Add(new PwDeletedObject(pg.getUuid(), new Date()));

			++uDeleted;
		}

		return uDeleted;
	}

	public int DeleteUnusedCustomIcons()
	{
		final List<PwUuid> lToDelete = new ArrayList<PwUuid>();
		for(PwCustomIcon pwci : m_vCustomIcons)
			lToDelete.add(pwci.getUuid());

		final GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			PwUuid pwUuid = pg.getCustomIconUuid();
			if((pwUuid == null) || pwUuid.Equals(PwUuid.Zero)) return true;

			for(int i = 0; i < lToDelete.size(); ++i)
			{
				if(lToDelete.get(i).equals(pwUuid))
				{
					lToDelete.remove(i);
					break;
				}
			}

			return true;
		}};

		EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
		{
			PwUuid pwUuid = pe.getCustomIconUuid();
			if((pwUuid == null) || pwUuid.Equals(PwUuid.Zero)) return true;

			for(int i = 0; i < lToDelete.size(); ++i)
			{
				if(lToDelete.get(i).equals(pwUuid))
				{
					lToDelete.remove(i);
					break;
				}
			}

			return true;
        }};

		gh.delegate(m_pgRootGroup);
		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, eh);

		int uDeleted = 0;
		for(PwUuid pwDel : lToDelete)
		{
			int nIndex = GetCustomIconIndex(pwDel);
			if(nIndex < 0) { assert false; continue; }

			m_vCustomIcons.remove(nIndex);
			++uDeleted;
		}

		if(uDeleted > 0) m_bUINeedsIconUpdate = true;
		return uDeleted;
	}
}
