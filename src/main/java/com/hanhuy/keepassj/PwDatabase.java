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
		if(m_bPrimaryCreated == false) m_bPrimaryCreated = true;

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

	/// <summary>
	/// Synchronize the current database with another one.
	/// </summary>
	/// <param name="pdSource">Input database to synchronize with. This input
	/// database is used to update the current one, but is not modified! You
	/// must copy the current object if you want a second instance of the
	/// synchronized database. The input database must not be seen as valid
	/// database any more after calling <c>Synchronize</c>.</param>
	/// <param name="mm">Merge method.</param>
	/// <param name="slStatus">Logger to report status messages to.
	/// May be <c>null</c>.</param>
	public void MergeIn(final PwDatabase pdSource, final PwMergeMethod mm,
		final IStatusLogger slStatus)
	{
		if(pdSource == null) throw new IllegalArgumentException("pdSource");

		PwGroup pgOrgStructure = m_pgRootGroup.CloneStructure();
		PwGroup pgSrcStructure = pdSource.m_pgRootGroup.CloneStructure();

		if(mm == PwMergeMethod.CreateNewUuids)
		{
			pdSource.getRootGroup().CreateNewItemUuids(true, true, true);
			pdSource.getRootGroup().setUuid(new PwUuid(true));
		}

		GroupHandler gh = new GroupHandler() {
        public boolean delegate(PwGroup pg)
		{
			// if(pg == pdSource.m_pgRootGroup) return true;

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
				else if(pgSourceParent == pdSource.m_pgRootGroup)
					pgLocalContainer = m_pgRootGroup;
				else
					pgLocalContainer = m_pgRootGroup.FindGroup(pgSourceParent.getUuid(), true);
				assert pgLocalContainer != null;
				if(pgLocalContainer == null) pgLocalContainer = m_pgRootGroup;

				PwGroup pgNew = new PwGroup(false, false);
				pgNew.setUuid(pg.getUuid());
				pgNew.AssignProperties(pg, false, true);
				pgLocalContainer.AddGroup(pgNew, true);
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

		EntryHandler eh = new EntryHandler() {
        public boolean delegate(PwEntry pe)
		{
			PwEntry peLocal = m_pgRootGroup.FindEntry(pe.getUuid(), true);
			if(peLocal == null)
			{
				PwGroup pgSourceParent = pe.getParentGroup();
				PwGroup pgLocalContainer;
				if(pgSourceParent == pdSource.m_pgRootGroup)
					pgLocalContainer = m_pgRootGroup;
				else
					pgLocalContainer = m_pgRootGroup.FindGroup(pgSourceParent.getUuid(), true);
				assert pgLocalContainer != null;
				if(pgLocalContainer == null) pgLocalContainer = m_pgRootGroup;

				PwEntry peNew = new PwEntry(false, false);
				peNew.setUuid(pe.getUuid());
				peNew.AssignProperties(pe, false, true, true);
				pgLocalContainer.AddEntry(peNew, true);
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

		gh.delegate(pdSource.getRootGroup());
		if(!pdSource.getRootGroup().TraverseTree(TraversalMethod.PreOrder, gh, eh))
			throw new UnsupportedOperationException();

		IStatusLogger slPrevStatus = m_slStatus;
		m_slStatus = slStatus;

		if(mm == PwMergeMethod.Synchronize)
		{
			ApplyDeletions(pdSource.m_vDeletedObjects, true);
			ApplyDeletions(m_vDeletedObjects, false);

			PwObjectPool ppOrgGroups = PwObjectPool.FromGroupRecursive(
				pgOrgStructure, false);
			PwObjectPool ppSrcGroups = PwObjectPool.FromGroupRecursive(
				pgSrcStructure, false);
			PwObjectPool ppOrgEntries = PwObjectPool.FromGroupRecursive(
				pgOrgStructure, true);
			PwObjectPool ppSrcEntries = PwObjectPool.FromGroupRecursive(
				pgSrcStructure, true);

			RelocateGroups(ppOrgGroups, ppSrcGroups);
			ReorderGroups(ppOrgGroups, ppSrcGroups);
			RelocateEntries(ppOrgEntries, ppSrcEntries);
			ReorderEntries(ppOrgEntries, ppSrcEntries);
			assert !HasDuplicateUuids();
		}

		// Must be called *after* merging groups, because group UUIDs
		// are required for recycle bin and entry template UUIDs
		MergeInDbProperties(pdSource, mm);

		MergeInCustomIcons(pdSource);

		MaintainBackups();

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

	private void ApplyDeletions(final PwObjectList<PwDeletedObject> listDelObjects,
		boolean bCopyDeletionInfoToLocal)
	{
		assert listDelObjects != null;
        if(listDelObjects == null) throw new IllegalArgumentException("listDelObjects");

		final LinkedList<PwGroup> listGroupsToDelete = new LinkedList<PwGroup>();
		final LinkedList<PwEntry> listEntriesToDelete = new LinkedList<PwEntry>();

		GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			if(pg == m_pgRootGroup) return true;

			for(PwDeletedObject pdo : listDelObjects)
			{
				if(pg.getUuid().Equals(pdo.getUuid()))
				{
					if(TimeUtil.Compare(pg.getLastModificationTime(),
						pdo.getDeletionTime(), true) < 0)
						listGroupsToDelete.addLast(pg);
				}
			}

			return ((m_slStatus != null) ? m_slStatus.ContinueWork() : true);
		}};

		EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
		{
			for(PwDeletedObject pdo : listDelObjects)
			{
				if(pe.getUuid().Equals(pdo.getUuid()))
				{
					if(TimeUtil.Compare(pe.getLastModificationTime(),
						pdo.getDeletionTime(), true) < 0)
						listEntriesToDelete.addLast(pe);
				}
			}

			return ((m_slStatus != null) ? m_slStatus.ContinueWork() : true);
		}};

		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, eh);

		for(PwGroup pg : listGroupsToDelete)
			pg.getParentGroup().getGroups().Remove(pg);
		for(PwEntry pe : listEntriesToDelete)
			pe.getParentGroup().getEntries().Remove(pe);

		if(bCopyDeletionInfoToLocal)
		{
			for (PwDeletedObject pdoNew : listDelObjects)
			{
				boolean bCopy = true;

				for (PwDeletedObject pdoLocal : m_vDeletedObjects)
				{
					if(pdoNew.getUuid().Equals(pdoLocal.getUuid()))
					{
						bCopy = false;

						if(pdoNew.getDeletionTime().getTime() > pdoLocal.getDeletionTime().getTime())
							pdoLocal.setDeletionTime(pdoNew.getDeletionTime());

						break;
					}
				}

				if(bCopy) m_vDeletedObjects.Add(pdoNew);
			}
		}
	}

	private void RelocateGroups(PwObjectPool ppOrgStructure,
		PwObjectPool ppSrcStructure)
	{
		PwObjectList<PwGroup> vGroups = m_pgRootGroup.GetGroups(true);

		for(PwGroup pg : vGroups)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			// PwGroup pgOrg = pgOrgStructure.FindGroup(pg.Uuid, true);
			IStructureItem ptOrg = ppOrgStructure.Get(pg.getUuid());
			if(ptOrg == null) continue;
			// PwGroup pgSrc = pgSrcStructure.FindGroup(pg.Uuid, true);
			IStructureItem ptSrc = ppSrcStructure.Get(pg.getUuid());
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
				pg.setLocationChanged((ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime()) ?
					ptSrc.getLocationChanged() : ptOrg.getLocationChanged());
				continue;
			}

			if(ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime())
			{
				PwGroup pgLocal = m_pgRootGroup.FindGroup(pgSrcParent.getUuid(), true);
				if(pgLocal == null) { assert false; continue; }

				if(pgLocal.IsContainedIn(pg)) continue;

				pg.getParentGroup().getGroups().Remove(pg);
				pgLocal.AddGroup(pg, true);
				pg.setLocationChanged(ptSrc.getLocationChanged());
			}
			else
			{
				assert pg.getParentGroup().getUuid().Equals(pgOrgParent.getUuid());
				assert pg.getLocationChanged().equals(ptOrg.getLocationChanged());
			}
		}

		assert m_pgRootGroup.GetGroups(true).getUCount() == vGroups.getUCount();
	}

	private void RelocateEntries(PwObjectPool ppOrgStructure,
		PwObjectPool ppSrcStructure)
	{
		PwObjectList<PwEntry> vEntries = m_pgRootGroup.GetEntries(true);

		for(PwEntry pe : vEntries)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			// PwEntry peOrg = pgOrgStructure.FindEntry(pe.Uuid, true);
			IStructureItem ptOrg = ppOrgStructure.Get(pe.getUuid());
			if(ptOrg == null) continue;
			// PwEntry peSrc = pgSrcStructure.FindEntry(pe.Uuid, true);
			IStructureItem ptSrc = ppSrcStructure.Get(pe.getUuid());
			if(ptSrc == null) continue;

			PwGroup pgOrg = ptOrg.getParentGroup();
			PwGroup pgSrc = ptSrc.getParentGroup();
			if(pgOrg.getUuid().Equals(pgSrc.getUuid()))
			{
				pe.setLocationChanged((ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime()) ?
					ptSrc.getLocationChanged() : ptOrg.getLocationChanged());
				continue;
			}

			if(ptSrc.getLocationChanged().getTime() > ptOrg.getLocationChanged().getTime())
			{
				PwGroup pgLocal = m_pgRootGroup.FindGroup(pgSrc.getUuid(), true);
				if(pgLocal == null) { assert false; continue; }

				pe.getParentGroup().getEntries().Remove(pe);
				pgLocal.AddEntry(pe, true);
				pe.setLocationChanged(ptSrc.getLocationChanged());
			}
			else
			{
				assert pe.getParentGroup().getUuid().Equals(pgOrg.getUuid());
				assert pe.getLocationChanged() == ptOrg.getLocationChanged();
			}
		}

		assert m_pgRootGroup.GetEntries(true).getUCount() == vEntries.getUCount();
	}

	private void ReorderGroups(final PwObjectPool ppOrgStructure,
		final PwObjectPool ppSrcStructure)
	{
		GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			ReorderObjectList(pg.getGroups(), ppOrgStructure,
				ppSrcStructure, false);
			return true;
		}};

		ReorderObjectList(m_pgRootGroup.getGroups(), ppOrgStructure,
			ppSrcStructure, false);
		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, null);
	}

	private void ReorderEntries(final PwObjectPool ppOrgStructure,
		final PwObjectPool ppSrcStructure)
	{
		GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg)
		{
			ReorderObjectList(pg.getEntries(), ppOrgStructure,
				ppSrcStructure, true);
			return true;
		}};

		ReorderObjectList(m_pgRootGroup.getEntries(), ppOrgStructure,
			ppSrcStructure, true);
		m_pgRootGroup.TraverseTree(TraversalMethod.PreOrder, gh, null);
	}

	private <T extends IStructureItem & IDeepCloneable<T>> void ReorderObjectList(PwObjectList<T> vItems,
		PwObjectPool ppOrgStructure, PwObjectPool ppSrcStructure, boolean bEntries)
	{
		if(!ObjectListRequiresReorder(vItems, ppOrgStructure, ppSrcStructure,
			bEntries)) return;

		PwObjectList<T> vOrgListItems = vItems.CloneShallow();


		Queue<Map.Entry<Integer, Integer>> qToDo = new LinkedList<Map.Entry<Integer, Integer>>();
		qToDo.add(Maps.immutableEntry(0, vItems.getUCount() - 1));

		while(qToDo.size() > 0)
		{
			if((m_slStatus != null) && !m_slStatus.ContinueWork()) break;

			Map.Entry<Integer, Integer> kvp = qToDo.poll();
			if(kvp.getValue() <= kvp.getKey()) { assert false; continue; }

			Queue<PwUuid> qRelBefore = new LinkedList<PwUuid>();
			Queue<PwUuid> qRelAfter = new LinkedList<PwUuid>();
			int uPivot = FindLocationChangedPivot(vItems, kvp, ppOrgStructure,
				ppSrcStructure, qRelBefore, qRelAfter, bEntries);
			T ptPivot = vItems.GetAt(uPivot);

			List<T> vToSort = vItems.GetRange(kvp.getKey(), kvp.getValue());
			Queue<T> qBefore = new LinkedList<T>();
			Queue<T> qAfter = new LinkedList<T>();
			boolean bBefore = true;

			for(T pt : vToSort)
			{
				if(pt == ptPivot) { bBefore = false; continue; }

				boolean bAdded = false;
				for(PwUuid puBefore : qRelBefore)
				{
					if(puBefore.Equals(pt.getUuid()))
					{
						qBefore.add(pt);
						bAdded = true;
						break;
					}
				}
				if(bAdded) continue;

				for(PwUuid puAfter : qRelAfter)
				{
					if(puAfter.Equals(pt.getUuid()))
					{
						qAfter.add(pt);
						bAdded = true;
						break;
					}
				}
				if(bAdded) continue;

				if(bBefore) qBefore.add(pt);
				else qAfter.add(pt);
			}
			assert bBefore == false;

			int uPos = kvp.getKey();
			while(qBefore.size() > 0) vItems.SetAt(uPos++, qBefore.poll());
			vItems.SetAt(uPos++, ptPivot);
			while(qAfter.size() > 0) vItems.SetAt(uPos++, qAfter.poll());
			assert uPos == (kvp.getValue() + 1);

			int iNewPivot = vItems.IndexOf(ptPivot);
			if((iNewPivot < (int)kvp.getKey()) || (iNewPivot > (int)kvp.getValue()))
			{
				assert false;
				continue;
			}

			if((iNewPivot - 1) > (int)kvp.getKey())
				qToDo.add(Maps.immutableEntry(kvp.getKey(),
                        (int) (iNewPivot - 1)));

			if((iNewPivot + 1) < (int)kvp.getValue())
				qToDo.add(Maps.immutableEntry((int) (iNewPivot + 1),
                        kvp.getValue()));
		}

if (false) { // debug
		for(T ptItem : vOrgListItems)
		{
			assert vItems.IndexOf(ptItem) >= 0;
		}
}
	}

	private static <T extends IStructureItem & IDeepCloneable<T>> int FindLocationChangedPivot(PwObjectList<T> vItems,
		Map.Entry<Integer, Integer> kvpRange, PwObjectPool ppOrgStructure,
		PwObjectPool ppSrcStructure, Queue<PwUuid> qBefore, Queue<PwUuid> qAfter,
		boolean bEntries)
	{
		int uPosMax = kvpRange.getKey();
		Date dtMax = new Date(0);
		List<IStructureItem> vNeighborSrc = null;

		for(int u = kvpRange.getKey(); u <= kvpRange.getValue(); ++u)
		{
			T pt = vItems.GetAt(u);

			// IStructureItem ptOrg = pgOrgStructure.FindObject(pt.Uuid, true, bEntries);
			IStructureItem ptOrg = ppOrgStructure.Get(pt.getUuid());
			if((ptOrg != null) && (ptOrg.getLocationChanged().getTime() > dtMax.getTime()))
			{
				uPosMax = u;
				dtMax = ptOrg.getLocationChanged(); // No 'continue'

				PwGroup pgParent = ptOrg.getParentGroup();
				if(pgParent != null)
					vNeighborSrc = pgParent.GetObjects(false, bEntries);
				else
				{
					assert false; // Org root should be excluded
					vNeighborSrc = new ArrayList<IStructureItem>();
					vNeighborSrc.add(ptOrg);
				}
			}

			// IStructureItem ptSrc = pgSrcStructure.FindObject(pt.Uuid, true, bEntries);
			IStructureItem ptSrc = ppSrcStructure.Get(pt.getUuid());
			if((ptSrc != null) && (ptSrc.getLocationChanged().getTime() > dtMax.getTime()))
			{
				uPosMax = u;
				dtMax = ptSrc.getLocationChanged(); // No 'continue'

				PwGroup pgParent = ptSrc.getParentGroup();
				if(pgParent != null)
					vNeighborSrc = pgParent.GetObjects(false, bEntries);
				else
				{
					// pgParent may be null (for the source root group)
					vNeighborSrc = new ArrayList<IStructureItem>();
					vNeighborSrc.add(ptSrc);
				}
			}
		}

		GetNeighborItems(vNeighborSrc, vItems.GetAt(uPosMax).getUuid(), qBefore, qAfter);
		return uPosMax;
	}

	private static void GetNeighborItems(List<IStructureItem> vItems,
		PwUuid pwPivot, Queue<PwUuid> qBefore, Queue<PwUuid> qAfter)
	{
		qBefore.clear();
		qAfter.clear();

		// Checks after clearing the queues
		if(vItems == null) { assert false; return; } // No throw

		boolean bBefore = true;
		for(int i = 0; i < vItems.size(); ++i)
		{
			PwUuid pw = vItems.get(i).getUuid();

			if(pw.Equals(pwPivot)) bBefore = false;
			else if(bBefore) qBefore.add(pw);
			else qAfter.add(pw);
		}
		assert !bBefore;
	}

	/// <summary>
	/// Method to check whether a reordering is required. This fast test
	/// allows to skip the reordering routine, resulting in a large
	/// performance increase.
	/// </summary>
	private <T extends IStructureItem & IDeepCloneable<T>> boolean ObjectListRequiresReorder(PwObjectList<T> vItems,
		PwObjectPool ppOrgStructure, PwObjectPool ppSrcStructure, boolean bEntries)
	{
		assert ppOrgStructure.ContainsOnlyType(bEntries ? PwEntry.class : PwGroup.class);
		assert ppSrcStructure.ContainsOnlyType(bEntries ? PwEntry.class : PwGroup.class);
		if(vItems.getUCount() <= 1) return false;

		if((m_slStatus != null) && !m_slStatus.ContinueWork()) return false;

		T ptFirst = vItems.GetAt(0);
		// IStructureItem ptOrg = pgOrgStructure.FindObject(ptFirst.Uuid, true, bEntries);
		IStructureItem ptOrg = ppOrgStructure.Get(ptFirst.getUuid());
		if(ptOrg == null) return true;
		// IStructureItem ptSrc = pgSrcStructure.FindObject(ptFirst.Uuid, true, bEntries);
		IStructureItem ptSrc = ppSrcStructure.Get(ptFirst.getUuid());
		if(ptSrc == null) return true;

		if(ptFirst.getParentGroup() == null) { assert false; return true; }
		PwGroup pgOrgParent = ptOrg.getParentGroup();
		if(pgOrgParent == null) return true; // Root might be in tree
		PwGroup pgSrcParent = ptSrc.getParentGroup();
		if(pgSrcParent == null) return true; // Root might be in tree

		if(!ptFirst.getParentGroup().getUuid().Equals(pgOrgParent.getUuid())) return true;
		if(!pgOrgParent.getUuid().Equals(pgSrcParent.getUuid())) return true;

		List<IStructureItem> lOrg = pgOrgParent.GetObjects(false, bEntries);
		List<IStructureItem> lSrc = pgSrcParent.GetObjects(false, bEntries);
		if(vItems.getUCount() != (int)lOrg.size()) return true;
		if(lOrg.size() != lSrc.size()) return true;

		for(int u = 0; u < vItems.getUCount(); ++u)
		{
			IStructureItem pt = vItems.GetAt(u);
			assert pt.getParentGroup() == ptFirst.getParentGroup();

			if(!pt.getUuid().Equals(lOrg.get((int) u).getUuid())) return true;
			if(!pt.getUuid().Equals(lSrc.get((int) u).getUuid())) return true;
			if(!pt.getLocationChanged().equals(lOrg.get(u).getLocationChanged())) return true;
			if(!pt.getLocationChanged().equals(lSrc.get(u).getLocationChanged())) return true;
		}

		return false;
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
				if(pe.getHistory().GetAt(uEnum).getLastModificationTime().getTime() !=
					peSource.getHistory().GetAt(uEnum).getLastModificationTime().getTime())
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
		HashMap<PwUuid, Object> d = new HashMap<PwUuid, Object>(nTotal);
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
		HashMap<PwUuid, Object> d = new HashMap<PwUuid, Object>(nTotal);

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
