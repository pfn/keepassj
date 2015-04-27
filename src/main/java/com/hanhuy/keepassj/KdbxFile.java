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
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.common.io.BaseEncoding;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import org.xmlpull.v1.XmlSerializer;

import java.io.*;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


	/// <summary>
	/// Serialization to KeePass KDBX files.
	/// </summary>
	public class KdbxFile
	{
		/// <summary>
		/// File identifier, first 32-bit value.
		/// </summary>
		static final int FileSignature1 = 0x9AA2D903;

		/// <summary>
		/// File identifier, second 32-bit value.
		/// </summary>
		static final int FileSignature2 = 0xB54BFB67;

		/// <summary>
		/// File version of files saved by the current <c>KdbxFile</c> class.
		/// KeePass 2.07 has version 1.01, 2.08 has 1.02, 2.09 has 2.00,
		/// 2.10 has 2.02, 2.11 has 2.04, 2.15 has 3.00, 2.20 has 3.01.
		/// The first 2 bytes are critical (i.e. loading will fail, if the
		/// file version is too high), the last 2 bytes are informational.
		/// </summary>
		private final static int FileVersion32 = 0x00030001;

		private final static int FileVersionCriticalMask = 0xFFFF0000;

		// KeePass 1.x signature
		final static int FileSignatureOld1 = 0x9AA2D903;
		final static int FileSignatureOld2 = 0xB54BFB65;
		// KeePass 2.x pre-release (alpha and beta) signature
		final static int FileSignaturePreRelease1 = 0x9AA2D903;
		final static int FileSignaturePreRelease2 = 0xB54BFB66;

		private final static String ElemDocNode = "KeePassFile";
		private final static String ElemMeta = "Meta";
		private final static String ElemRoot = "Root";
		private final static String ElemGroup = "Group";
		private final static String ElemEntry = "Entry";

		private final static String ElemGenerator = "Generator";
		private final static String ElemHeaderHash = "HeaderHash";
		private final static String ElemDbName = "DatabaseName";
		private final static String ElemDbNameChanged = "DatabaseNameChanged";
		private final static String ElemDbDesc = "DatabaseDescription";
		private final static String ElemDbDescChanged = "DatabaseDescriptionChanged";
		private final static String ElemDbDefaultUser = "DefaultUserName";
		private final static String ElemDbDefaultUserChanged = "DefaultUserNameChanged";
		private final static String ElemDbMntncHistoryDays = "MaintenanceHistoryDays";
		private final static String ElemDbColor = "Color";
		private final static String ElemDbKeyChanged = "MasterKeyChanged";
		private final static String ElemDbKeyChangeRec = "MasterKeyChangeRec";
		private final static String ElemDbKeyChangeForce = "MasterKeyChangeForce";
		private final static String ElemRecycleBinEnabled = "RecycleBinEnabled";
		private final static String ElemRecycleBinUuid = "RecycleBinUUID";
		private final static String ElemRecycleBinChanged = "RecycleBinChanged";
		private final static String ElemEntryTemplatesGroup = "EntryTemplatesGroup";
		private final static String ElemEntryTemplatesGroupChanged = "EntryTemplatesGroupChanged";
		private final static String ElemHistoryMaxItems = "HistoryMaxItems";
		private final static String ElemHistoryMaxSize = "HistoryMaxSize";
		private final static String ElemLastSelectedGroup = "LastSelectedGroup";
		private final static String ElemLastTopVisibleGroup = "LastTopVisibleGroup";

		private final static String ElemMemoryProt = "MemoryProtection";
		private final static String ElemProtTitle = "ProtectTitle";
		private final static String ElemProtUserName = "ProtectUserName";
		private final static String ElemProtPassword = "ProtectPassword";
		private final static String ElemProtUrl = "ProtectURL";
		private final static String ElemProtNotes = "ProtectNotes";
		// private final static String ElemProtAutoHide = "AutoEnableVisualHiding";

		private final static String ElemCustomIcons = "CustomIcons";
		private final static String ElemCustomIconItem = "Icon";
		private final static String ElemCustomIconItemID = "UUID";
		private final static String ElemCustomIconItemData = "Data";

		private final static String ElemAutoType = "AutoType";
		private final static String ElemHistory = "History";

		private final static String ElemName = "Name";
		private final static String ElemNotes = "Notes";
		private final static String ElemUuid = "UUID";
		private final static String ElemIcon = "IconID";
		private final static String ElemCustomIconID = "CustomIconUUID";
		private final static String ElemFgColor = "ForegroundColor";
		private final static String ElemBgColor = "BackgroundColor";
		private final static String ElemOverrideUrl = "OverrideURL";
		private final static String ElemTimes = "Times";
		private final static String ElemTags = "Tags";

		private final static String ElemCreationTime = "CreationTime";
		private final static String ElemLastModTime = "LastModificationTime";
		private final static String ElemLastAccessTime = "LastAccessTime";
		private final static String ElemExpiryTime = "ExpiryTime";
		private final static String ElemExpires = "Expires";
		private final static String ElemUsageCount = "UsageCount";
		private final static String ElemLocationChanged = "LocationChanged";

		private final static String ElemGroupDefaultAutoTypeSeq = "DefaultAutoTypeSequence";
		private final static String ElemEnableAutoType = "EnableAutoType";
		private final static String ElemEnableSearching = "EnableSearching";

		private final static String ElemString = "String";
		private final static String ElemBinary = "Binary";
		private final static String ElemKey = "Key";
		private final static String ElemValue = "Value";

		private final static String ElemAutoTypeEnabled = "Enabled";
		private final static String ElemAutoTypeObfuscation = "DataTransferObfuscation";
		private final static String ElemAutoTypeDefaultSeq = "DefaultSequence";
		private final static String ElemAutoTypeItem = "Association";
		private final static String ElemWindow = "Window";
		private final static String ElemKeystrokeSequence = "KeystrokeSequence";

		private final static String ElemBinaries = "Binaries";

		private final static String AttrId = "ID";
		private final static String AttrRef = "Ref";
		private final static String AttrProtected = "Protected";
		private final static String AttrProtectedInMemPlainXml = "ProtectInMemory";
		private final static String AttrCompressed = "Compressed";

		private final static String ElemIsExpanded = "IsExpanded";
		private final static String ElemLastTopVisibleEntry = "LastTopVisibleEntry";

		private final static String ElemDeletedObjects = "DeletedObjects";
		private final static String ElemDeletedObject = "DeletedObject";
		private final static String ElemDeletionTime = "DeletionTime";

		private final static String ValFalse = "False";
		private final static String ValTrue = "True";

		private final static String ElemCustomData = "CustomData";
		private final static String ElemStringDictExItem = "Item";

		private PwDatabase m_pwDatabase; // Not null, see constructor

		private XmlSerializer m_xmlWriter = null;
		private CryptoRandomStream m_randomStream = null;
		private KdbxFormat m_format = KdbxFormat.Default;
		private IStatusLogger m_slLogger = null;

		private byte[] m_pbMasterSeed = null;
		private byte[] m_pbTransformSeed = null;
		private byte[] m_pbEncryptionIV = null;
		private byte[] m_pbProtectedStreamKey = null;
		private byte[] m_pbStreamStartBytes = null;

		// ArcFourVariant only for compatibility; KeePass will default to a
		// different (more secure) algorithm when *writing* databases
		private CrsAlgorithm m_craInnerRandomStream = CrsAlgorithm.ArcFourVariant;

		private Map<String, ProtectedBinary> m_dictBinPool =
			new HashMap<String, ProtectedBinary>();

		private byte[] m_pbHashOfHeader = null;
		private byte[] m_pbHashOfFileOnDisk = null;

		private final Date m_dtNow = new Date(); // Cache current time

		private final static int NeutralLanguageOffset = 0x100000; // 2^20, see 32-bit Unicode specs
		private final static int NeutralLanguageIDSec = 0x7DC5C; // See 32-bit Unicode specs
		private final static int NeutralLanguageID = NeutralLanguageOffset + NeutralLanguageIDSec;
		private static boolean m_bLocalizedNames = false;

		private enum KdbxHeaderFieldID
		{
			EndOfHeader,
			Comment,
			CipherID ,
			CompressionFlags,
			MasterSeed,
			TransformSeed,
			TransformRounds,
			EncryptionIV,
			ProtectedStreamKey,
			StreamStartBytes,
			InnerRandomStreamID
		}

		public byte[] getHashOfFileOnDisk()
		{
			return m_pbHashOfFileOnDisk;
		}

		private boolean m_bRepairMode = false;
		public boolean getRepairMode()
		{
			return m_bRepairMode;
		}
        public void setRepairMode(boolean value) { m_bRepairMode = value; }

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
		/// Default constructor.
		/// </summary>
		/// <param name="pwDataStore">The <c>PwDatabase</c> instance that the
		/// class will load file data into or use to create a KDBX file.</param>
		public KdbxFile(PwDatabase pwDataStore)
		{
			assert pwDataStore != null;
			if(pwDataStore == null) throw new IllegalArgumentException("pwDataStore");

			m_pwDatabase = pwDataStore;
		}

		/// <summary>
		/// Call this once to determine the current localization settings.
		/// </summary>
		public static void DetermineLanguageId()
		{
			// Test if localized names should be used. If localized names are used,
			// the m_bLocalizedNames value must be set to true. By default, localized
			// names should be used! (Otherwise characters could be corrupted
			// because of different code pages).
				int uTest = 0;
				for(char ch : PwDatabase.getLocalizedAppName().toCharArray())
					uTest = uTest * 5 + ch;

				m_bLocalizedNames = (uTest != NeutralLanguageID);
		}

		private void BinPoolBuild(PwGroup pgDataSource)
		{
			m_dictBinPool = new HashMap<String, ProtectedBinary>();

			if(pgDataSource == null) { assert false; return; }

			EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe)
			{
				for(PwEntry peHistory : pe.getHistory())
				{
					BinPoolAdd(peHistory.getBinaries());
				}

				BinPoolAdd(pe.getBinaries());
				return true;
			}};

			pgDataSource.TraverseTree(TraversalMethod.PreOrder, null, eh);
		}

		private void BinPoolAdd(ProtectedBinaryDictionary dict)
		{
			for(Map.Entry<String, ProtectedBinary> kvp : dict)
			{
				BinPoolAdd(kvp.getValue());
			}
		}

		private void BinPoolAdd(ProtectedBinary pb)
		{
			if(pb == null) { assert false; return; }

			if(BinPoolFind(pb) != null) return; // Exists already

			m_dictBinPool.put(String.valueOf(m_dictBinPool.size()), pb);
		}

		private String BinPoolFind(ProtectedBinary pb)
		{
			if(pb == null) { assert false; return null; }

			for(Map.Entry<String, ProtectedBinary> kvp : m_dictBinPool.entrySet())
			{
				if(pb.Equals(kvp.getValue())) return kvp.getKey();
			}

			return null;
		}

		private ProtectedBinary BinPoolGet(String strKey)
		{
			if(strKey == null) { assert false; return null; }

            return m_dictBinPool.get(strKey);
		}

		private static void SaveBinary(String strName, ProtectedBinary pb,
			String strSaveDir) throws IOException
		{
			if(pb == null) { assert false; return; }

			if(Strings.isNullOrEmpty(strName)) strName = "File.bin";

			String strPath;
			int iTry = 1;
			do
			{
				strPath = UrlUtil.EnsureTerminatingSeparator(strSaveDir, false);

				String strExt = UrlUtil.GetExtension(strName);
				String strDesc = UrlUtil.StripExtension(strName);

				strPath += strDesc;
				if(iTry > 1)
					strPath += " (" + String.valueOf(iTry) +
						")";

				if(!Strings.isNullOrEmpty(strExt)) strPath += "." + strExt;

				++iTry;
			}
			while(new File(strPath).exists());

			FileOutputStream fs = new FileOutputStream(strPath, false);
            try {
                byte[] pbData = pb.ReadData();
                fs.write(pbData, 0, pbData.length);
            } finally {
                fs.close();
            }
        }

        // KdbxFile.Read.cs
            /// <summary>
            /// Serialization to KeePass KDBX files.
            /// </summary>
            /// <summary>
            /// Load a KDB file from a file.
            /// </summary>
            /// <param name="strFilePath">File to load.</param>
            /// <param name="kdbFormat">Format specifier.</param>
            /// <param name="slLogger">Status logger (optional).</param>
            public void Load(String strFilePath, KdbxFormat kdbFormat, IStatusLogger slLogger)
            throws IOException
            {
                IOConnectionInfo ioc = IOConnectionInfo.FromPath(strFilePath);
                Load(IOConnection.OpenRead(ioc), kdbFormat, slLogger);
            }

            /// <summary>
            /// Load a KDB file from a stream.
            /// </summary>
            /// <param name="sSource">Stream to read the data from. Must contain
            /// a KDBX stream.</param>
            /// <param name="kdbFormat">Format specifier.</param>
            /// <param name="slLogger">Status logger (optional).</param>
            public void Load(InputStream sSource, KdbxFormat kdbFormat, IStatusLogger slLogger)
            throws IOException
            {
                assert sSource != null;
                if(sSource == null) throw new IllegalArgumentException("sSource");

                m_format = kdbFormat;
                m_slLogger = slLogger;

                HashingInputStreamEx hashedStream = new HashingInputStreamEx(sSource);

                Charset encNoBom = StrUtil.Utf8;
                try
                {
                    BinaryReaderEx br = null;
                    BinaryReaderEx brDecrypted = null;
                    InputStream readerStream = null;

                    if(kdbFormat == KdbxFormat.Default)
                    {
                        br = new BinaryReaderEx(hashedStream, encNoBom, "file corrupted");
                        ReadHeader(br);

                        InputStream sDecrypted = AttachStreamDecryptor(hashedStream);
                        if((sDecrypted == null) || (sDecrypted == hashedStream))
                            throw new SecurityException("stream decryption failure");

                        brDecrypted = new BinaryReaderEx(sDecrypted, encNoBom, "file corrupted");
                        byte[] pbStoredStartBytes = brDecrypted.ReadBytes(32);

                        if((m_pbStreamStartBytes == null) || (m_pbStreamStartBytes.length != 32))
                            throw new KdbxFileFormatException("stream start bytes");

                        for(int iStart = 0; iStart < 32; ++iStart)
                        {
                            if(pbStoredStartBytes[iStart] != m_pbStreamStartBytes[iStart])
                                throw new InvalidCompositeKeyException(
                                        BaseEncoding.base16().encode(pbStoredStartBytes) +
                                                " != " +
                                                BaseEncoding.base16().encode(m_pbStreamStartBytes)
                                );
                        }

                        InputStream sHashed = new HashedBlockStream.Input(sDecrypted,
                                !m_bRepairMode);

                        if(m_pwDatabase.getCompression() == PwCompressionAlgorithm.GZip)
                            readerStream = new GZIPInputStream(sHashed);
                        else readerStream = sHashed;
                    }
                    else if(kdbFormat == KdbxFormat.PlainXml)
                        readerStream = hashedStream;
                    else { assert false; throw new KdbxFileFormatException("KdbFormat"); }

                    if(kdbFormat != KdbxFormat.PlainXml) // Is an encrypted format
                    {
                        if(m_pbProtectedStreamKey == null)
                        {
                            assert false;
                            throw new SecurityException("Invalid protected stream key!");
                        }

                        m_randomStream = new CryptoRandomStream(m_craInnerRandomStream,
                                m_pbProtectedStreamKey);
                    }
                    else m_randomStream = null; // No random stream for plain-text files

                    ReadXmlStreamed(readerStream, hashedStream);
                    // ReadXmlDom(readerStream);

                    readerStream.close();
                    // GC.KeepAlive(br);
                    // GC.KeepAlive(brDecrypted);
                }
                catch(Exception e) // Thrown on invalid padding
                {
                    throw new KdbxFileFormatException(e);
                }
                finally {
                    try {
                        CommonCleanUpRead(sSource, hashedStream);
                    } catch (AssertionError e) {
                    }
                }
            }

            private void CommonCleanUpRead(InputStream sSource, HashingInputStreamEx hashedStream)
                    throws IOException
            {
                hashedStream.close();
                m_pbHashOfFileOnDisk = hashedStream.getHash();

                sSource.close();

                // Reset memory protection settings (to always use reasonable
                // defaults)
                m_pwDatabase.setMemoryProtection(new MemoryProtectionConfig());

                // Remove old backups (this call is required here in order to apply
                // the default history maintenance settings for people upgrading from
                // KeePass <= 2.14 to >= 2.15; also it ensures history integrity in
                // case a different application has created the KDBX file and ignored
                // the history maintenance settings)
                m_pwDatabase.MaintainBackups(); // Don't mark database as modified

                m_pbHashOfHeader = null;
            }

            private void ReadHeader(BinaryReaderEx br)
                    throws IOException
            {
                ByteArrayOutputStream msHeader = new ByteArrayOutputStream();
                assert br.getCopyDataTo() == null;
                br.setCopyDataTo(msHeader);

                byte[] pbSig1 = br.ReadBytes(4);
                int uSig1 = MemUtil.BytesToUInt32(pbSig1);
                byte[] pbSig2 = br.ReadBytes(4);
                int uSig2 = MemUtil.BytesToUInt32(pbSig2);

                if((uSig1 == FileSignatureOld1) && (uSig2 == FileSignatureOld2))
                    throw new OldFormatException(PwDefs.ShortProductName + " 1.x",
                    OldFormatException.OldFormatType.KeePass1x);

                if((uSig1 == FileSignature1) && (uSig2 == FileSignature2)) { }
                else if((uSig1 == FileSignaturePreRelease1) && (uSig2 ==
                        FileSignaturePreRelease2)) { }
                else throw new KdbxFileFormatException("invalid signature");

                byte[] pb = br.ReadBytes(4);
                int uVersion = MemUtil.BytesToUInt32(pb);
                if((uVersion & FileVersionCriticalMask) > (FileVersion32 & FileVersionCriticalMask))
                    throw new KdbxFileFormatException("Unsupported file version" +
                            "\n" + "new version required");

                while(true)
                {
                    if(!ReadHeaderField(br))
                        break;
                }

                br.setCopyDataTo(null);
                byte[] pbHeader = msHeader.toByteArray();
                msHeader.close();
                m_pbHashOfHeader = sha256().digest(pbHeader);
            }

            private boolean ReadHeaderField(BinaryReaderEx brSource)
                    throws IOException
            {
                assert brSource != null;
                if(brSource == null) throw new IllegalArgumentException("brSource");

                byte btFieldID = brSource.ReadByte();
                short uSize = MemUtil.BytesToUInt16(brSource.ReadBytes(2));

                byte[] pbData = null;
                if(uSize > 0)
                {
                    String strPrevExcpText = brSource.getReadExceptionText();
                    brSource.setReadExceptionText("file header end early");

                    pbData = brSource.ReadBytes(uSize);

                    brSource.setReadExceptionText(strPrevExcpText);
                }

                boolean bResult = true;
                KdbxHeaderFieldID kdbID = KdbxHeaderFieldID.values()[btFieldID];
                switch(kdbID)
                {
                    case EndOfHeader:
                        bResult = false; // Returning false indicates end of header
                        break;

                    case CipherID:
                        SetCipher(pbData);
                        break;

                    case CompressionFlags:
                        SetCompressionFlags(pbData);
                        break;

                    case MasterSeed:
                        m_pbMasterSeed = pbData;
                        CryptoRandom.getInstance().AddEntropy(pbData);
                        break;

                    case TransformSeed:
                        m_pbTransformSeed = pbData;
                        CryptoRandom.getInstance().AddEntropy(pbData);
                        break;

                    case TransformRounds:
                        m_pwDatabase.setKeyEncryptionRounds(MemUtil.BytesToUInt64(pbData));
                        break;

                    case EncryptionIV:
                        m_pbEncryptionIV = pbData;
                        break;

                    case ProtectedStreamKey:
                        m_pbProtectedStreamKey = pbData;
                        CryptoRandom.getInstance().AddEntropy(pbData);
                        break;

                    case StreamStartBytes:
                        m_pbStreamStartBytes = pbData;
                        break;

                    case InnerRandomStreamID:
                        SetInnerRandomStreamID(pbData);
                        break;

                    default:
                        assert false;
                        if(m_slLogger != null)
                            m_slLogger.SetText("unknown header id" + ": " +
                            kdbID + "!", LogStatusType.Warning);
                        break;
                }

                return bResult;
            }

            private void SetCipher(byte[] pbID)
            {
                if((pbID == null) || (pbID.length != 16))
                    throw new KdbxFileFormatException("unknown cipher");

                m_pwDatabase.setDataCipherUuid(new PwUuid(pbID));
            }

            private void SetCompressionFlags(byte[] pbFlags)
            {
                int nID = (int)MemUtil.BytesToUInt32(pbFlags);
                if((nID < 0) || (nID >= PwCompressionAlgorithm.Count.ordinal()))
                    throw new KdbxFileFormatException("unknown file compression type");

                m_pwDatabase.setCompression(PwCompressionAlgorithm.values()[nID]);
            }

            private void SetInnerRandomStreamID(byte[] pbID)
            {
                int uID = MemUtil.BytesToUInt32(pbID);
                if(uID >= CrsAlgorithm.Count.ordinal())
                    throw new KdbxFileFormatException("unknown cipher");

                m_craInnerRandomStream = CrsAlgorithm.values()[uID];
            }

            private InputStream AttachStreamDecryptor(InputStream s)
            {
                ByteArrayOutputStream ms = new ByteArrayOutputStream();

                assert m_pbMasterSeed.length == 32;
                if(m_pbMasterSeed.length != 32)
                    throw new KdbxFileFormatException("master seed length invalid");
                ms.write(m_pbMasterSeed, 0, 32);

                byte[] pKey32 = m_pwDatabase.getMasterKey().GenerateKey32(m_pbTransformSeed,
                        m_pwDatabase.getKeyEncryptionRounds()).ReadData();
                if((pKey32 == null) || (pKey32.length != 32))
                    throw new SecurityException("invalid composite key");
                ms.write(pKey32, 0, 32);

                byte[] aesKey = sha256().digest(ms.toByteArray());

                Arrays.fill(pKey32, 0, 32, (byte)0);

                if((aesKey == null) || (aesKey.length != 32))
                    throw new SecurityException("final key creation failed");

                ICipherEngine iEngine = CipherPool.getGlobalPool().GetCipher(m_pwDatabase.getDataCipherUuid());
                if(iEngine == null) throw new SecurityException("Unknown file cipher");
                return iEngine.DecryptStream(s, aesKey, m_pbEncryptionIV);
            }

            @Deprecated
            public static List<PwEntry> ReadEntries(PwDatabase pwDatabase, InputStream msData)
                    throws IOException
            {
                return ReadEntries(msData);
            }

            /// <summary>
            /// Read entries from a stream.
            /// </summary>
            /// <param name="msData">Input stream to read the entries from.</param>
            /// <returns>Extracted entries.</returns>
            public static List<PwEntry> ReadEntries(InputStream msData) throws IOException
            {
			/* KdbxFile f = new KdbxFile(pwDatabase);
			f.m_format = KdbxFormat.PlainXml;

			XmlDocument doc = new XmlDocument();
			doc.Load(msData);

			XmlElement el = doc.DocumentElement;
			if(el.Name != ElemRoot) throw new FormatException();

			List<PwEntry> vEntries = new List<PwEntry>();

			for(XmlNode xmlChild : el.ChildNodes)
			{
				if(xmlChild.Name == ElemEntry)
				{
					PwEntry pe = f.ReadEntry(xmlChild);
					pe.Uuid = new PwUuid(true);

					for(PwEntry peHistory : pe.History)
						peHistory.Uuid = pe.Uuid;

					vEntries.Add(pe);
				}
				else { assert false; }
			}

			return vEntries; */

                PwDatabase pd = new PwDatabase();
                KdbxFile f = new KdbxFile(pd);
                f.Load(msData, KdbxFormat.PlainXml, null);

                List<PwEntry> vEntries = new ArrayList<PwEntry>();
                for(PwEntry pe : pd.getRootGroup().getEntries())
                {
                    pe.SetUuid(new PwUuid(true), true);
                    vEntries.add(pe);
                }

                return vEntries;
            }

        // KdbxFile.Read.Streamed.cs
    private enum KdbContext
    {
        Null,
        KeePassFile,
        Meta,
        Root,
        MemoryProtection,
        CustomIcons,
        CustomIcon,
        Binaries,
        CustomData,
        CustomDataItem,
        RootDeletedObjects,
        DeletedObject,
        Group,
        GroupTimes,
        Entry,
        EntryTimes,
        EntryString,
        EntryBinary,
        EntryAutoType,
        EntryAutoTypeItem,
        EntryHistory
    }

    private boolean m_bReadNextNode = true;
    private Stack<PwGroup> m_ctxGroups = new Stack<PwGroup>();
    private PwGroup m_ctxGroup = null;
    private PwEntry m_ctxEntry = null;
    private String m_ctxStringName = null;
    private ProtectedString m_ctxStringValue = null;
    private String m_ctxBinaryName = null;
    private ProtectedBinary m_ctxBinaryValue = null;
    private String m_ctxATName = null;
    private String m_ctxATSeq = null;
    private boolean m_bEntryInHistory = false;
    private PwEntry m_ctxHistoryBase = null;
    private PwDeletedObject m_ctxDeletedObject = null;
    private PwUuid m_uuidCustomIconID = PwUuid.Zero;
    private byte[] m_pbCustomIconData = null;
    private String m_strCustomDataKey = null;
    private String m_strCustomDataValue = null;

    private void ReadXmlStreamed(InputStream readerStream, InputStream sParentStream) throws IOException, XmlPullParserException {
        ReadDocumentStreamed(CreateXmlReader(readerStream), sParentStream);
    }

        /*
    static XmlReaderSettings CreateStdXmlReaderSettings() {
        {
            XmlReaderSettings xrs = new XmlReaderSettings();

            xrs.CloseInput = true;
            xrs.IgnoreComments = true;
            xrs.IgnoreProcessingInstructions = true;
            xrs.IgnoreWhitespace = true;

            xrs.ProhibitDtd = true;
            xrs.ValidationType = ValidationType.None;

            return xrs;
        }
        */


    private static XmlPullParser CreateXmlReader(InputStream readerStream)
    {
        try {
            XmlPullParserFactory fact = XmlPullParserFactory.newInstance();
            fact.setFeature(XmlPullParser.FEATURE_VALIDATION, false);
//            XmlReaderSettings xrs = CreateStdXmlReaderSettings();
            XmlPullParser xr = fact.newPullParser();
            xr.setInput(readerStream, "utf-8");
            return xr;
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private void ReadDocumentStreamed(XmlPullParser xr, InputStream sParentStream)
            throws IOException, XmlPullParserException
    {
        assert xr != null;
        if(xr == null) throw new IllegalArgumentException("xr");

        m_ctxGroups.clear();
        m_dictBinPool = new HashMap<String, ProtectedBinary>();

        KdbContext ctx = KdbContext.Null;

        int uTagCounter = 0;

        boolean bSupportsStatus = (m_slLogger != null);
        long lStreamLength = 1;
        /*
        try
        {
            sParentStream.Position.ToString(); // Test Position support
            lStreamLength = sParentStream.Length;
        }
        catch(Exception e) { bSupportsStatus = false; }
        */
        if(lStreamLength <= 0) { assert false; lStreamLength = 1; }

        m_bReadNextNode = true;

        while(true)
        {
            if(m_bReadNextNode)
            {
                if (xr.next() == XmlPullParser.END_DOCUMENT) break;
            }
            else m_bReadNextNode = true;

            switch(xr.getEventType())
            {
                case XmlPullParser.START_TAG:
                    ctx = ReadXmlElement(ctx, xr);
                    if (xr.getEventType() == XmlPullParser.START_TAG &&
                            xr.isEmptyElementTag()) xr.next(); // skip empty END_TAG
                    break;

                case XmlPullParser.END_TAG:
                    ctx = EndXmlElement(ctx, xr);
                    break;

                case XmlPullParser.DOCDECL:
                    break; // Ignore

                default:
//                    assert false;
                    break;
            }

            ++uTagCounter;
            /*
            if(((uTagCounter % 256) == 0) && bSupportsStatus)
            {
                assert lStreamLength == sParentStream.Length;
                int uPct = (int)((sParentStream.Position * 100) /
                        lStreamLength);

                // Clip percent value in case the stream reports incorrect
                // position/length values (M120413)
                if(uPct > 100) { assert false; uPct = 100; }

                m_slLogger.SetProgress(uPct);
            }
            */
        }

        assert ctx == KdbContext.Null;
        if(ctx != KdbContext.Null) throw new KdbxFileFormatException("non null context");

        assert m_ctxGroups.size() == 0;
        if(m_ctxGroups.size() != 0) throw new KdbxFileFormatException("nonzero groups");
    }

    private KdbContext ReadXmlElement(KdbContext ctx, XmlPullParser xr) throws XmlPullParserException, IOException {
        switch(ctx)
        {
            case Null:
                if(Objects.equal(xr.getName(), ElemDocNode))
                    return SwitchContext(ctx, KdbContext.KeePassFile, xr);
                else ReadUnknown(xr);
                break;

            case KeePassFile:
                if(xr.getName().equals(ElemMeta))
                    return SwitchContext(ctx, KdbContext.Meta, xr);
                else if(xr.getName().equals(ElemRoot))
                    return SwitchContext(ctx, KdbContext.Root, xr);
                else ReadUnknown(xr);
                break;

            case Meta:
                if(xr.getName().equals(ElemGenerator))
                    ReadString(xr); // Ignore
                else if(xr.getName().equals(ElemHeaderHash))
                {
                    String strHash = ReadString(xr);
                    if(!Strings.isNullOrEmpty(strHash) && (m_pbHashOfHeader != null) &&
                            !m_bRepairMode)
                    {
                        byte[] pbHash = BaseEncoding.base64().decode(strHash);
                        if(!MemUtil.ArraysEqual(pbHash, m_pbHashOfHeader))
                            throw new KdbxFileFormatException("file corrupted");
                    }
                }
                else if(xr.getName().equals(ElemDbName))
                    m_pwDatabase.setName(ReadString(xr));
                else if(xr.getName().equals(ElemDbNameChanged))
                    m_pwDatabase.setNameChanged(ReadTime(xr));
                else if(xr.getName().equals(ElemDbDesc))
                    m_pwDatabase.setDescription(ReadString(xr));
                else if(xr.getName().equals(ElemDbDescChanged))
                    m_pwDatabase.setDescriptionChanged(ReadTime(xr));
                else if(xr.getName().equals(ElemDbDefaultUser))
                    m_pwDatabase.setDefaultUserName(ReadString(xr));
                else if(xr.getName().equals(ElemDbDefaultUserChanged))
                    m_pwDatabase.setDefaultUserNameChanged(ReadTime(xr));
                else if(xr.getName().equals(ElemDbMntncHistoryDays))
                    m_pwDatabase.setMaintenanceHistoryDays(ReadUInt(xr, 365));
                else if(xr.getName().equals(ElemDbColor))
                {
                    String strColor = ReadString(xr);
                    if(!Strings.isNullOrEmpty(strColor))
                        m_pwDatabase.setColor(ColorTranslator.FromHtml(strColor));
                }
                else if(xr.getName().equals(ElemDbKeyChanged))
                    m_pwDatabase.setMasterKeyChanged(ReadTime(xr));
                else if(xr.getName().equals(ElemDbKeyChangeRec))
                    m_pwDatabase.setMasterKeyChangeRec(ReadLong(xr, -1));
                else if(xr.getName().equals(ElemDbKeyChangeForce))
                    m_pwDatabase.setMasterKeyChangeForce(ReadLong(xr, -1));
                else if(xr.getName().equals(ElemMemoryProt))
                    return SwitchContext(ctx, KdbContext.MemoryProtection, xr);
                else if(xr.getName().equals(ElemCustomIcons))
                    return SwitchContext(ctx, KdbContext.CustomIcons, xr);
                else if(xr.getName().equals(ElemRecycleBinEnabled))
                    m_pwDatabase.setRecycleBinEnabled(ReadBool(xr, true));
                else if(xr.getName().equals(ElemRecycleBinUuid))
                    m_pwDatabase.setRecycleBinUuid(ReadUuid(xr));
                else if(xr.getName().equals(ElemRecycleBinChanged))
                    m_pwDatabase.setRecycleBinChanged(ReadTime(xr));
                else if(xr.getName().equals(ElemEntryTemplatesGroup))
                    m_pwDatabase.setEntryTemplatesGroup(ReadUuid(xr));
                else if(xr.getName().equals(ElemEntryTemplatesGroupChanged))
                    m_pwDatabase.setEntryTemplatesGroupChanged(ReadTime(xr));
                else if(xr.getName().equals(ElemHistoryMaxItems))
                    m_pwDatabase.setHistoryMaxItems(ReadInt(xr, -1));
                else if(xr.getName().equals(ElemHistoryMaxSize))
                    m_pwDatabase.setHistoryMaxSize(ReadLong(xr, -1));
                else if(xr.getName().equals(ElemLastSelectedGroup)) {
                    m_pwDatabase.setLastSelectedGroup(ReadUuid(xr));
                }
                else if(xr.getName().equals(ElemLastTopVisibleGroup))
                    m_pwDatabase.setLastTopVisibleGroup(ReadUuid(xr));
                else if(xr.getName().equals(ElemBinaries))
                    return SwitchContext(ctx, KdbContext.Binaries, xr);
                else if(xr.getName().equals(ElemCustomData))
                    return SwitchContext(ctx, KdbContext.CustomData, xr);
                else ReadUnknown(xr);
                break;

            case MemoryProtection:
                if(xr.getName().equals(ElemProtTitle))
                    m_pwDatabase.getMemoryProtection().ProtectTitle = ReadBool(xr, false);
                else if(xr.getName().equals(ElemProtUserName))
                    m_pwDatabase.getMemoryProtection().ProtectUserName = ReadBool(xr, false);
                else if(xr.getName().equals(ElemProtPassword))
                    m_pwDatabase.getMemoryProtection().ProtectPassword = ReadBool(xr, true);
                else if(xr.getName().equals(ElemProtUrl))
                    m_pwDatabase.getMemoryProtection().ProtectUrl = ReadBool(xr, false);
                else if(xr.getName().equals(ElemProtNotes))
                    m_pwDatabase.getMemoryProtection().ProtectNotes = ReadBool(xr, false);
                    // else if(xr.Name == ElemProtAutoHide)
                    //	m_pwDatabase.MemoryProtection.AutoEnableVisualHiding = ReadBool(xr, true);
                else ReadUnknown(xr);
                break;

            case CustomIcons:
                if(xr.getName().equals(ElemCustomIconItem))
                    return SwitchContext(ctx, KdbContext.CustomIcon, xr);
                else ReadUnknown(xr);
                break;

            case CustomIcon:
                if(xr.getName().equals(ElemCustomIconItemID))
                    m_uuidCustomIconID = ReadUuid(xr);
                else if(xr.getName().equals(ElemCustomIconItemData))
                {
                    String strData = ReadString(xr);
                    if(!Strings.isNullOrEmpty(strData))
                        m_pbCustomIconData = BaseEncoding.base64().decode(strData);
                    else { assert false; }
                }
                else ReadUnknown(xr);
                break;

            case Binaries:
                if(xr.getName().equals(ElemBinary))
                {
                    String strKey = xr.getAttributeValue(null, AttrId);
                    if(strKey != null)
                    {
                        ProtectedBinary pbData = ReadProtectedBinary(xr);

                        m_dictBinPool.put(strKey == null ? "" : strKey, pbData);
                    }
                    else ReadUnknown(xr);
                }
                else ReadUnknown(xr);
                break;

            case CustomData:
                if(xr.getName().equals(ElemStringDictExItem))
                    return SwitchContext(ctx, KdbContext.CustomDataItem, xr);
                else ReadUnknown(xr);
                break;

            case CustomDataItem:
                if(xr.getName().equals(ElemKey))
                    m_strCustomDataKey = ReadString(xr);
                else if(xr.getName().equals(ElemValue))
                    m_strCustomDataValue = ReadString(xr);
                else ReadUnknown(xr);
                break;

            case Root:
                if(xr.getName().equals(ElemGroup))
                {
                    assert m_ctxGroups.size() == 0;
                    if(m_ctxGroups.size() != 0) throw new KdbxFileFormatException("groups size not 0");

                    m_pwDatabase.setRootGroup(new PwGroup(false, false));
                    m_ctxGroups.push(m_pwDatabase.getRootGroup());
                    m_ctxGroup = m_ctxGroups.peek();

                    return SwitchContext(ctx, KdbContext.Group, xr);
                }
                else if(xr.getName().equals(ElemDeletedObjects))
                    return SwitchContext(ctx, KdbContext.RootDeletedObjects, xr);
                else ReadUnknown(xr);
                break;

            case Group:
                if(xr.getName().equals(ElemUuid))
                    m_ctxGroup.setUuid(ReadUuid(xr));
                else if(xr.getName().equals(ElemName))
                    m_ctxGroup.setName(ReadString(xr));
                else if(xr.getName().equals(ElemNotes))
                    m_ctxGroup.setNotes(ReadString(xr));
                else if(xr.getName().equals(ElemIcon))
                    m_ctxGroup.setIconId(PwIcon.values()[ReadInt(xr, PwIcon.Folder.ordinal())]);
                else if(xr.getName().equals(ElemCustomIconID))
                    m_ctxGroup.setCustomIconUuid(ReadUuid(xr));
                else if(xr.getName().equals(ElemTimes))
                    return SwitchContext(ctx, KdbContext.GroupTimes, xr);
                else if(xr.getName().equals(ElemIsExpanded))
                    m_ctxGroup.setExpanded(ReadBool(xr, true));
                else if(xr.getName().equals(ElemGroupDefaultAutoTypeSeq))
                    m_ctxGroup.setDefaultAutoTypeSequence(ReadString(xr));
                else if(xr.getName().equals(ElemEnableAutoType))
                    m_ctxGroup.setEnableAutoType(StrUtil.StringToBoolEx(ReadString(xr)));
                else if(xr.getName().equals(ElemEnableSearching))
                    m_ctxGroup.setEnableSearching(StrUtil.StringToBoolEx(ReadString(xr)));
                else if(xr.getName().equals(ElemLastTopVisibleEntry))
                    m_ctxGroup.setLastTopVisibleEntry(ReadUuid(xr));
                else if(xr.getName().equals(ElemGroup))
                {
                    m_ctxGroup = new PwGroup(false, false);
                    m_ctxGroups.peek().AddGroup(m_ctxGroup, true);

                    m_ctxGroups.push(m_ctxGroup);

                    return SwitchContext(ctx, KdbContext.Group, xr);
                }
                else {
                    if (xr.getName().equals(ElemEntry)) {
                        m_ctxEntry = new PwEntry(false, false);
                        m_ctxGroup.AddEntry(m_ctxEntry, true);

                        m_bEntryInHistory = false;
                        return SwitchContext(ctx, KdbContext.Entry, xr);
                    } else ReadUnknown(xr);
                }
                break;

            case Entry:
                if(xr.getName().equals(ElemUuid)) {
                    m_ctxEntry.setUuid(ReadUuid(xr));
                }
                else if(xr.getName().equals(ElemIcon))
                    m_ctxEntry.setIconId(PwIcon.values()[ReadInt(xr, PwIcon.Key.ordinal())]);
                else if(xr.getName().equals(ElemCustomIconID))
                    m_ctxEntry.setCustomIconUuid(ReadUuid(xr));
                else if(xr.getName().equals(ElemFgColor))
                {
                    String strColor = ReadString(xr);
                    if(!Strings.isNullOrEmpty(strColor))
                        m_ctxEntry.setForegroundColor(ColorTranslator.FromHtml(strColor));
                }
                else if(xr.getName().equals(ElemBgColor))
                {
                    String strColor = ReadString(xr);
                    if(!Strings.isNullOrEmpty(strColor))
                        m_ctxEntry.setBackgroundColor(ColorTranslator.FromHtml(strColor));
                }
                else if(xr.getName().equals(ElemOverrideUrl))
                    m_ctxEntry.setOverrideUrl(ReadString(xr));
                else if(xr.getName().equals(ElemTags))
                    m_ctxEntry.setTags(StrUtil.StringToTags(ReadString(xr)));
                else if(xr.getName().equals(ElemTimes))
                    return SwitchContext(ctx, KdbContext.EntryTimes, xr);
                else if(xr.getName().equals(ElemString))
                    return SwitchContext(ctx, KdbContext.EntryString, xr);
                else if(xr.getName().equals(ElemBinary))
                    return SwitchContext(ctx, KdbContext.EntryBinary, xr);
                else if(xr.getName().equals(ElemAutoType))
                    return SwitchContext(ctx, KdbContext.EntryAutoType, xr);
                else if(xr.getName().equals(ElemHistory))
                {
                    assert !m_bEntryInHistory;

                    if(!m_bEntryInHistory)
                    {
                        m_ctxHistoryBase = m_ctxEntry;
                        return SwitchContext(ctx, KdbContext.EntryHistory, xr);
                    }
                    else ReadUnknown(xr);
                }
                else ReadUnknown(xr);
                break;

            case GroupTimes:
            case EntryTimes:
                ITimeLogger tl = ((ctx == KdbContext.GroupTimes) ?
                        (ITimeLogger)m_ctxGroup : (ITimeLogger)m_ctxEntry);
                assert tl != null;

                if(xr.getName().equals(ElemCreationTime))
                    tl.setCreationTime(ReadTime(xr));
                else if(xr.getName().equals(ElemLastModTime))
                    tl.setLastModificationTime(ReadTime(xr));
                else if(xr.getName().equals(ElemLastAccessTime))
                    tl.setLastAccessTime(ReadTime(xr));
                else if(xr.getName().equals(ElemExpiryTime))
                    tl.setExpiryTime(ReadTime(xr));
                else if(xr.getName().equals(ElemExpires))
                    tl.setExpires(ReadBool(xr, false));
                else if(xr.getName().equals(ElemUsageCount))
                    tl.setUsageCount(ReadULong(xr, 0));
                else if(xr.getName().equals(ElemLocationChanged))
                    tl.setLocationChanged(ReadTime(xr));
                else ReadUnknown(xr);
                break;

            case EntryString:
                if(xr.getName().equals(ElemKey))
                    m_ctxStringName = ReadString(xr);
                else if(xr.getName().equals(ElemValue))
                    m_ctxStringValue = ReadProtectedString(xr);
                else ReadUnknown(xr);
                break;

            case EntryBinary:
                if(xr.getName().equals(ElemKey))
                    m_ctxBinaryName = ReadString(xr);
                else if(xr.getName().equals(ElemValue))
                    m_ctxBinaryValue = ReadProtectedBinary(xr);
                else ReadUnknown(xr);
                break;

            case EntryAutoType:
                if(xr.getName().equals(ElemAutoTypeEnabled))
                    m_ctxEntry.getAutoType().setEnabled(ReadBool(xr, true));
                else if(xr.getName().equals(ElemAutoTypeObfuscation))
                    m_ctxEntry.getAutoType().setObfuscationOptions(
                            AutoTypeObfuscationOptions.values()[ReadInt(xr, 0)]);
                else if(xr.getName().equals(ElemAutoTypeDefaultSeq))
                    m_ctxEntry.getAutoType().setDefaultSequence(ReadString(xr));
                else if(xr.getName().equals(ElemAutoTypeItem))
                    return SwitchContext(ctx, KdbContext.EntryAutoTypeItem, xr);
                else ReadUnknown(xr);
                break;

            case EntryAutoTypeItem:
                if(xr.getName().equals(ElemWindow))
                    m_ctxATName = ReadString(xr);
                else if(xr.getName().equals(ElemKeystrokeSequence))
                    m_ctxATSeq = ReadString(xr);
                else ReadUnknown(xr);
                break;

            case EntryHistory:
                if(xr.getName().equals(ElemEntry))
                {
                    m_ctxEntry = new PwEntry(false, false);
                    m_ctxHistoryBase.getHistory().Add(m_ctxEntry);

                    m_bEntryInHistory = true;
                    return SwitchContext(ctx, KdbContext.Entry, xr);
                }
                else ReadUnknown(xr);
                break;

            case RootDeletedObjects:
                if(xr.getName().equals(ElemDeletedObject))
                {
                    m_ctxDeletedObject = new PwDeletedObject();
                    m_pwDatabase.getDeletedObjects().Add(m_ctxDeletedObject);

                    return SwitchContext(ctx, KdbContext.DeletedObject, xr);
                }
                else ReadUnknown(xr);
                break;

            case DeletedObject:
                if(xr.getName().equals(ElemUuid))
                    m_ctxDeletedObject.setUuid(ReadUuid(xr));
                else if(xr.getName().equals(ElemDeletionTime))
                    m_ctxDeletedObject.setDeletionTime(ReadTime(xr));
                else ReadUnknown(xr);
                break;

            default:
                ReadUnknown(xr);
                break;
        }

        return ctx;
    }

    private KdbContext EndXmlElement(KdbContext ctx, XmlPullParser xr)
            throws XmlPullParserException, IOException
    {
        assert xr.getEventType() == XmlPullParser.END_TAG;

        if((ctx == KdbContext.KeePassFile) && (xr.getName().equals(ElemDocNode)))
            return KdbContext.Null;
        else if((ctx == KdbContext.Meta) && (xr.getName().equals(ElemMeta)))
            return KdbContext.KeePassFile;
        else if((ctx == KdbContext.Root) && (xr.getName().equals(ElemRoot)))
            return KdbContext.KeePassFile;
        else if((ctx == KdbContext.MemoryProtection) && (xr.getName().equals(ElemMemoryProt)))
            return KdbContext.Meta;
        else if((ctx == KdbContext.CustomIcons) && (xr.getName().equals(ElemCustomIcons)))
            return KdbContext.Meta;
        else if((ctx == KdbContext.CustomIcon) && (xr.getName().equals(ElemCustomIconItem)))
        {
            if(!m_uuidCustomIconID.Equals(PwUuid.Zero) &&
                    (m_pbCustomIconData != null))
                m_pwDatabase.getCustomIcons().add(new PwCustomIcon(
                        m_uuidCustomIconID, m_pbCustomIconData));
            else { assert false; }

            m_uuidCustomIconID = PwUuid.Zero;
            m_pbCustomIconData = null;

            return KdbContext.CustomIcons;
        }
        else if((ctx == KdbContext.Binaries) && (xr.getName().equals(ElemBinaries)))
            return KdbContext.Meta;
        else if((ctx == KdbContext.CustomData) && (xr.getName().equals(ElemCustomData)))
            return KdbContext.Meta;
        else if((ctx == KdbContext.CustomDataItem) && (xr.getName().equals(ElemStringDictExItem)))
        {
            if((m_strCustomDataKey != null) && (m_strCustomDataValue != null))
                m_pwDatabase.getCustomData().Set(m_strCustomDataKey, m_strCustomDataValue);
            else { assert false; }

            m_strCustomDataKey = null;
            m_strCustomDataValue = null;

            return KdbContext.CustomData;
        }
        else if((ctx == KdbContext.Group) && (xr.getName().equals(ElemGroup)))
        {
            if(PwUuid.Zero.Equals(m_ctxGroup.getUuid()))
                m_ctxGroup.setUuid(new PwUuid(true)); // No assert (import)

            m_ctxGroups.pop();

            if(m_ctxGroups.size() == 0)
            {
                m_ctxGroup = null;
                return KdbContext.Root;
            }
            else
            {
                m_ctxGroup = m_ctxGroups.peek();
                return KdbContext.Group;
            }
        }
        else if((ctx == KdbContext.GroupTimes) && (xr.getName().equals(ElemTimes)))
            return KdbContext.Group;
        else if((ctx == KdbContext.Entry) && (xr.getName().equals(ElemEntry)))
        {
            // Create new UUID if absent
            if(PwUuid.Zero.Equals(m_ctxEntry.getUuid()))
                m_ctxEntry.setUuid(new PwUuid(true)); // No assert (import)

            if(m_bEntryInHistory)
            {
                m_ctxEntry = m_ctxHistoryBase;
                return KdbContext.EntryHistory;
            }

            return KdbContext.Group;
        }
        else if((ctx == KdbContext.EntryTimes) && (xr.getName().equals(ElemTimes)))
            return KdbContext.Entry;
        else if((ctx == KdbContext.EntryString) && (xr.getName().equals(ElemString)))
        {
            m_ctxEntry.getStrings().Set(m_ctxStringName, m_ctxStringValue);
            m_ctxStringName = null;
            m_ctxStringValue = null;
            return KdbContext.Entry;
        }
        else if((ctx == KdbContext.EntryBinary) && (xr.getName().equals(ElemBinary)))
        {
            if(Strings.isNullOrEmpty(m_strDetachBins))
                m_ctxEntry.getBinaries().Set(m_ctxBinaryName, m_ctxBinaryValue);
            else
            {
                SaveBinary(m_ctxBinaryName, m_ctxBinaryValue, m_strDetachBins);

                m_ctxBinaryValue = null;
            }

            m_ctxBinaryName = null;
            m_ctxBinaryValue = null;
            return KdbContext.Entry;
        }
        else if((ctx == KdbContext.EntryAutoType) && (xr.getName().equals(ElemAutoType)))
            return KdbContext.Entry;
        else if((ctx == KdbContext.EntryAutoTypeItem) && (xr.getName().equals(ElemAutoTypeItem)))
        {
            AutoTypeAssociation atAssoc = new AutoTypeAssociation(m_ctxATName,
                    m_ctxATSeq);
            m_ctxEntry.getAutoType().Add(atAssoc);
            m_ctxATName = null;
            m_ctxATSeq = null;
            return KdbContext.EntryAutoType;
        }
        else if((ctx == KdbContext.EntryHistory) && (xr.getName().equals(ElemHistory)))
        {
            m_bEntryInHistory = false;
            return KdbContext.Entry;
        }
        else if((ctx == KdbContext.RootDeletedObjects) && (xr.getName().equals(ElemDeletedObjects)))
            return KdbContext.Root;
        else if((ctx == KdbContext.DeletedObject) && (xr.getName().equals(ElemDeletedObject)))
        {
            m_ctxDeletedObject = null;
            return KdbContext.RootDeletedObjects;
        }
        else
        {
            throw new KdbxFileFormatException("xml end tag failure: " + ctx + " => " + xr.getName());
        }
    }

    private String ReadString(XmlPullParser xr) throws XmlPullParserException, IOException
    {
        XorredBuffer xb = ProcessNode(xr);
        if(xb != null)
        {
            byte[] pb = xb.ReadPlainText();
            if(pb.length == 0) return "";
            return new String(pb, 0, pb.length, StrUtil.Utf8);
        }

        //m_bReadNextNode = false; // ReadElementString skips end tag
        return xr.nextText();
    }

    private String ReadStringRaw(XmlPullParser xr) throws XmlPullParserException, IOException
    {
        //m_bReadNextNode = false; // ReadElementString skips end tag
        return xr.nextText();
    }

    private boolean ReadBool(XmlPullParser xr, boolean bDefault)
            throws XmlPullParserException, IOException
    {
        String str = ReadString(xr);
        if(str.equals(ValTrue)) return true;
        else if(str.equals(ValFalse)) return false;

        assert false;
        return bDefault;
    }

    private PwUuid ReadUuid(XmlPullParser xr) throws XmlPullParserException, IOException
    {
        String str = ReadString(xr);
        if(Strings.isNullOrEmpty(str)) return PwUuid.Zero;
        return new PwUuid(BaseEncoding.base64().decode(str));
    }

    private int ReadInt(XmlPullParser xr, int nDefault)
            throws XmlPullParserException, IOException
    {
        String str = ReadString(xr);

        int[] n = new int[1];
        if(StrUtil.TryParseIntInvariant(str, n)) return n[0];

        // Backward compatibility
        if(StrUtil.TryParseInt(str, n)) return n[0];

        assert false;
        return nDefault;
    }

    private int ReadUInt(XmlPullParser xr, int uDefault) throws IOException, XmlPullParserException {
        String str = ReadString(xr);

        int[] u = new int[1];
        if(StrUtil.TryParseUIntInvariant(str, u)) return u[0];

        // Backward compatibility
        if(StrUtil.TryParseUInt(str, u)) return u[0];

        assert false;
        return uDefault;
    }

    private long ReadLong(XmlPullParser xr, long lDefault) throws IOException, XmlPullParserException {
        String str = ReadString(xr);

        long[] l = new long[1];
        if(StrUtil.TryParseLongInvariant(str, l)) return l[0];

        // Backward compatibility
        if(StrUtil.TryParseLong(str, l)) return l[0];

        assert false;
        return lDefault;
    }

    private long ReadULong(XmlPullParser xr, long uDefault) throws IOException, XmlPullParserException {
        return ReadLong(xr, uDefault);
    }

    private Date ReadTime(XmlPullParser xr) throws IOException, XmlPullParserException {
        String str = ReadString(xr);

        Date[] dt = new Date[1];
        if(TimeUtil.TryDeserializeUtc(str, dt)) return dt[0];

        assert false;
        return m_dtNow;
    }

    private ProtectedString ReadProtectedString(XmlPullParser xr) throws IOException, XmlPullParserException {
        XorredBuffer xb = ProcessNode(xr);
        if(xb != null) return new ProtectedString(true, xb);

        boolean bProtect = false;
        if(m_format == KdbxFormat.PlainXml)
        {
            String strProtect = xr.getAttributeValue(null, AttrProtectedInMemPlainXml);
            if(strProtect != null)
            {
                bProtect = ((strProtect != null) && (strProtect.equals(ValTrue)));
            }
        }

        ProtectedString ps = new ProtectedString(bProtect, ReadString(xr));
        return ps;
    }

    private ProtectedBinary ReadProtectedBinary(XmlPullParser xr) throws IOException, XmlPullParserException {
        String strRef = xr.getAttributeValue(null, AttrRef);
        if(strRef != null)
        {
                ProtectedBinary pb = BinPoolGet(strRef);
                if(pb != null) return pb;
                else { assert false; }
        }

        boolean bCompressed = false;

        bCompressed = ValTrue.equals(xr.getAttributeValue(null, AttrCompressed));

        XorredBuffer xb = ProcessNode(xr);
        if(xb != null)
        {
            assert !bCompressed; // See SubWriteValue(ProtectedBinary value)
            return new ProtectedBinary(true, xb);
        }

        String strValue = ReadString(xr);
        if(strValue.length() == 0) return new ProtectedBinary();

        byte[] pbData = BaseEncoding.base64().decode(strValue);
        if(bCompressed) pbData = MemUtil.Decompress(pbData);
        return new ProtectedBinary(false, pbData);
    }

    private void ReadUnknown(XmlPullParser xr) throws XmlPullParserException, IOException
    {
//        assert false; // Unknown node!

        if(xr.isEmptyElementTag()) return;

        String strUnknownName = xr.getName();
        ProcessNode(xr);

        int xrNodeType;
        while((xrNodeType = xr.next()) != XmlPullParser.END_DOCUMENT)
        {
            if(xrNodeType == XmlPullParser.END_TAG) break;
            if(xrNodeType != XmlPullParser.START_TAG) continue;

            ReadUnknown(xr);
        }

        assert xr.getName().equals(strUnknownName);
    }

    private XorredBuffer ProcessNode(XmlPullParser xr) throws IOException, XmlPullParserException {
        // assert xr.NodeType == XmlNodeType.Element;

        XorredBuffer xb = null;
        if(xr.getAttributeCount() > 0)
        {
                if(ValTrue.equals(xr.getAttributeValue(null, AttrProtected)))
                {
                    String strEncrypted = ReadStringRaw(xr);

                    byte[] pbEncrypted;
                    if(strEncrypted.length() > 0)
                        pbEncrypted = BaseEncoding.base64().decode(strEncrypted);
                    else pbEncrypted = new byte[0];

                    byte[] pbPad = m_randomStream.GetRandomBytes((int)pbEncrypted.length);

                    xb = new XorredBuffer(pbEncrypted, pbPad);
                }
        }

        return xb;
    }

    private static KdbContext SwitchContext(KdbContext ctxCurrent,
                                            KdbContext ctxNew, XmlPullParser xr) throws XmlPullParserException {
        if(xr.isEmptyElementTag()) return ctxCurrent;
        return ctxNew;
    }

        // KdbxFile.Write.cs
/// <summary>
/// Serialization to KeePass KDBX files.
/// </summary>
    // public void Save(String strFile, PwGroup pgDataSource, KdbxFormat format,
    //	IStatusLogger slLogger)
    // {
    //	boolean bMadeUnhidden = UrlUtil.UnhideFile(strFile);
    //
    //	IOConnectionInfo ioc = IOConnectionInfo.FromPath(strFile);
    //	this.Save(IOConnection.OpenWrite(ioc), pgDataSource, format, slLogger);
    //
    //	if(bMadeUnhidden) UrlUtil.HideFile(strFile, true); // Hide again
    // }

    /// <summary>
    /// Save the contents of the current <c>PwDatabase</c> to a KDBX file.
    /// </summary>
    /// <param name="sSaveTo">Stream to write the KDBX file into.</param>
    /// <param name="pgDataSource">Group containing all groups and
    /// entries to write. If <c>null</c>, the complete database will
    /// be written.</param>
    /// <param name="format">Format of the file to create.</param>
    /// <param name="slLogger">Logger that recieves status information.</param>
    public void Save(OutputStream sSaveTo, PwGroup pgDataSource, KdbxFormat format,
                     IStatusLogger slLogger) throws IOException {
        assert sSaveTo != null;
        if(sSaveTo == null) throw new IllegalArgumentException("sSaveTo");

        m_format = format;
        m_slLogger = slLogger;

        HashingOutputStreamEx hashedStream = new HashingOutputStreamEx(sSaveTo);

        Charset encNoBom = StrUtil.Utf8;
        CryptoRandom cr = CryptoRandom.getInstance();

        try
        {
            m_pbMasterSeed = cr.GetRandomBytes(32);
            m_pbTransformSeed = cr.GetRandomBytes(32);
            m_pbEncryptionIV = cr.GetRandomBytes(16);

            m_pbProtectedStreamKey = cr.GetRandomBytes(32);
            m_craInnerRandomStream = CrsAlgorithm.Salsa20;
            m_randomStream = new CryptoRandomStream(m_craInnerRandomStream,
                    m_pbProtectedStreamKey);

            m_pbStreamStartBytes = cr.GetRandomBytes(32);

            OutputStream writerStream;
            if(m_format == KdbxFormat.Default)
            {
                WriteHeader(hashedStream); // Also flushes the stream

                OutputStream sEncrypted = AttachStreamEncryptor(hashedStream);
                if((sEncrypted == null) || (sEncrypted == hashedStream))
                    throw new SecurityException("failed to create crypto stream");

                sEncrypted.write(m_pbStreamStartBytes, 0, m_pbStreamStartBytes.length);

                OutputStream sHashed = new HashedBlockStream.Output(sEncrypted, 0);

                if(m_pwDatabase.getCompression() == PwCompressionAlgorithm.GZip)
                    writerStream = new GZIPOutputStream(sHashed);
                else
                    writerStream = sHashed;
            }
            else if(m_format == KdbxFormat.PlainXml)
                writerStream = hashedStream;
            else { assert false; throw new KdbxFileFormatException("KdbFormat"); }

            XmlPullParserFactory fact = XmlPullParserFactory.newInstance();
            m_xmlWriter = fact.newSerializer();
            m_xmlWriter.setOutput(writerStream, "utf-8");
//                    new XmlTextWriter(writerStream, encNoBom);
            WriteDocument(pgDataSource);

            m_xmlWriter.flush();
            writerStream.close();
        } catch (XmlPullParserException e) {
            throw new RuntimeException(e);
        } finally { CommonCleanUpWrite(sSaveTo, hashedStream); }
    }

    private void CommonCleanUpWrite(OutputStream sSaveTo, HashingOutputStreamEx hashedStream)
            throws IOException
    {
        hashedStream.close();
        m_pbHashOfFileOnDisk = hashedStream.getHash();

        sSaveTo.close();

        m_xmlWriter = null;
        m_pbHashOfHeader = null;
    }

    private void WriteHeader(OutputStream s)
            throws IOException
    {
        ByteArrayOutputStream ms = new ByteArrayOutputStream();

        MemUtil.Write(ms, MemUtil.UInt32ToBytes(FileSignature1));
        MemUtil.Write(ms, MemUtil.UInt32ToBytes(FileSignature2));
        MemUtil.Write(ms, MemUtil.UInt32ToBytes(FileVersion32));

        WriteHeaderField(ms, KdbxHeaderFieldID.CipherID,
                m_pwDatabase.getDataCipherUuid().getUuidBytes());

        int nCprID = m_pwDatabase.getCompression().ordinal();
        WriteHeaderField(ms, KdbxHeaderFieldID.CompressionFlags,
                MemUtil.UInt32ToBytes((int)nCprID));

        WriteHeaderField(ms, KdbxHeaderFieldID.MasterSeed, m_pbMasterSeed);
        WriteHeaderField(ms, KdbxHeaderFieldID.TransformSeed, m_pbTransformSeed);
        WriteHeaderField(ms, KdbxHeaderFieldID.TransformRounds,
                MemUtil.UInt64ToBytes(m_pwDatabase.getKeyEncryptionRounds()));
        WriteHeaderField(ms, KdbxHeaderFieldID.EncryptionIV, m_pbEncryptionIV);
        WriteHeaderField(ms, KdbxHeaderFieldID.ProtectedStreamKey, m_pbProtectedStreamKey);
        WriteHeaderField(ms, KdbxHeaderFieldID.StreamStartBytes, m_pbStreamStartBytes);

        int nIrsID = m_craInnerRandomStream.ordinal();
        WriteHeaderField(ms, KdbxHeaderFieldID.InnerRandomStreamID,
                MemUtil.UInt32ToBytes((int)nIrsID));

        WriteHeaderField(ms, KdbxHeaderFieldID.EndOfHeader, new byte[]{
                (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' });

        byte[] pbHeader = ms.toByteArray();
        ms.close();

        m_pbHashOfHeader = sha256().digest(pbHeader);

        s.write(pbHeader, 0, pbHeader.length);
        s.flush();
    }

    private static void WriteHeaderField(OutputStream s, KdbxHeaderFieldID kdbID,
                                         byte[] pbData) throws IOException {
        s.write(kdbID.ordinal());

        if(pbData != null)
        {
            short uLength = (short)pbData.length;
            MemUtil.Write(s, MemUtil.UInt16ToBytes(uLength));

            if(uLength > 0) s.write(pbData, 0, pbData.length);
        }
        else MemUtil.Write(s, MemUtil.UInt16ToBytes((short)0));
    }

    private OutputStream AttachStreamEncryptor(OutputStream s) throws IOException
    {
        ByteArrayOutputStream ms = new ByteArrayOutputStream();

        assert m_pbMasterSeed != null;
        assert m_pbMasterSeed.length == 32;
        ms.write(m_pbMasterSeed, 0, 32);

        assert m_pwDatabase != null;
        assert m_pwDatabase.getMasterKey() != null;
        ProtectedBinary pbinKey = m_pwDatabase.getMasterKey().GenerateKey32(
                m_pbTransformSeed, m_pwDatabase.getKeyEncryptionRounds());
        assert pbinKey != null;
        if(pbinKey == null)
            throw new SecurityException("Invalid composite key");
        byte[] pKey32 = pbinKey.ReadData();
        if((pKey32 == null) || (pKey32.length != 32))
            throw new SecurityException("Invalid composite key");
        ms.write(pKey32, 0, 32);

        byte[] aesKey = sha256().digest(ms.toByteArray());

        ms.close();
        Arrays.fill(pKey32, 0, 32, (byte)0);

        assert CipherPool.getGlobalPool() != null;
        ICipherEngine iEngine = CipherPool.getGlobalPool().GetCipher(m_pwDatabase.getDataCipherUuid());
        if(iEngine == null) throw new SecurityException("Unknown cipher");
        return iEngine.EncryptStream(s, aesKey, m_pbEncryptionIV);
    }

    private void WriteDocument(PwGroup pgDataSource) throws IOException {
        assert m_xmlWriter != null;
        if(m_xmlWriter == null) throw new UnsupportedOperationException();

        PwGroup pgRoot = (pgDataSource != null ? pgDataSource : m_pwDatabase.getRootGroup());

        final int[] uNumGroups = new int[1], uNumEntries = new int[1], uCurEntry = { 0 };
        pgRoot.GetCounts(true, uNumGroups, uNumEntries);

        BinPoolBuild(pgRoot);

//        m_xmlWriter.Formatting = Formatting.Indented;
//        m_xmlWriter.IndentChar = '\t';
//        m_xmlWriter.Indentation = 1;
        m_xmlWriter.setProperty("http://xmlpull.org/v1/doc/properties.html#serializer-indentation", "\t");

        m_xmlWriter.startDocument("utf-8", true);
        m_xmlWriter.startTag(null, ElemDocNode);

        WriteMeta();

        m_xmlWriter.startTag(null, ElemRoot);
        StartGroup(pgRoot);

        final Stack<PwGroup> groupStack = new Stack<PwGroup>();
        groupStack.push(pgRoot);

        GroupHandler gh = new GroupHandler() { public boolean delegate(PwGroup pg) {
            assert pg != null;
            if (pg == null) throw new IllegalArgumentException("pg");

            while (true) {
                if (pg.getParentGroup().equals(groupStack.peek())) {
                    groupStack.push(pg);
                    try {
                        StartGroup(pg);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    break;
                } else {
                    groupStack.pop();
                    if (groupStack.size() <= 0) return false;

                    try {
                        EndGroup();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            return true;
        }};

        EntryHandler eh = new EntryHandler() { public boolean delegate(PwEntry pe) {
            assert pe != null;
            try {
                WriteEntry(pe, false);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            ++uCurEntry[0];
            if (m_slLogger != null)
                if (!m_slLogger.SetProgress((100 * uCurEntry[0]) / uNumEntries[0]))
                    return false;

            return true;
        }};

        if(!pgRoot.TraverseTree(TraversalMethod.PreOrder, gh, eh))
            throw new UnsupportedOperationException();

        while(groupStack.size() > 1)
        {
//            m_xmlWriter.WriteEndElement();
            EndGroup(); // FIXME TODO is this correct?
            groupStack.pop();
        }

        EndGroup();

        WriteList(ElemDeletedObjects, m_pwDatabase.getDeletedObjects());
        m_xmlWriter.endTag(null, ElemRoot); // Root

        m_xmlWriter.endTag(null, ElemDocNode); // ElemDocNode
        m_xmlWriter.endDocument();
    }

    private void WriteMeta() throws IOException {
        m_xmlWriter.startTag(null, ElemMeta);

        WriteObject(ElemGenerator, PwDatabase.getLocalizedAppName(), false); // Generator name

        if(m_pbHashOfHeader != null)
            WriteObject(ElemHeaderHash, BaseEncoding.base64().encode(
                    m_pbHashOfHeader), false);

        WriteObject(ElemDbName, m_pwDatabase.getName(), true);
        WriteObject(ElemDbNameChanged, m_pwDatabase.getNameChanged());
        WriteObject(ElemDbDesc, m_pwDatabase.getDescription(), true);
        WriteObject(ElemDbDescChanged, m_pwDatabase.getDescriptionChanged());
        WriteObject(ElemDbDefaultUser, m_pwDatabase.getDefaultUserName(), true);
        WriteObject(ElemDbDefaultUserChanged, m_pwDatabase.getDefaultUserNameChanged());
        WriteObject(ElemDbMntncHistoryDays, m_pwDatabase.getMaintenanceHistoryDays());
        WriteObject(ElemDbColor, StrUtil.ColorToUnnamedHtml(m_pwDatabase.getColor(), true), false);
        WriteObject(ElemDbKeyChanged, m_pwDatabase.getMasterKeyChanged());
        WriteObject(ElemDbKeyChangeRec, m_pwDatabase.getMasterKeyChangeRec());
        WriteObject(ElemDbKeyChangeForce, m_pwDatabase.getMasterKeyChangeForce());

        WriteList(ElemMemoryProt, m_pwDatabase.getMemoryProtection());

        WriteCustomIconList();

        WriteObject(ElemRecycleBinEnabled, m_pwDatabase.isRecycleBinEnabled());
        WriteObject(ElemRecycleBinUuid, m_pwDatabase.getRecycleBinUuid());
        WriteObject(ElemRecycleBinChanged, m_pwDatabase.getRecycleBinChanged());
        WriteObject(ElemEntryTemplatesGroup, m_pwDatabase.getEntryTemplatesGroup());
        WriteObject(ElemEntryTemplatesGroupChanged, m_pwDatabase.getEntryTemplatesGroupChanged());
        WriteObject(ElemHistoryMaxItems, m_pwDatabase.getHistoryMaxItems());
        WriteObject(ElemHistoryMaxSize, m_pwDatabase.getHistoryMaxSize());

        WriteObject(ElemLastSelectedGroup, m_pwDatabase.getLastSelectedGroup());
        WriteObject(ElemLastTopVisibleGroup, m_pwDatabase.getLastTopVisibleGroup());

        WriteBinPool();
        WriteList(ElemCustomData, m_pwDatabase.getCustomData());

        m_xmlWriter.endTag(null, ElemMeta);
    }

    private void StartGroup(PwGroup pg) throws IOException {
        m_xmlWriter.startTag(null, ElemGroup);
        WriteObject(ElemUuid, pg.getUuid());
        WriteObject(ElemName, pg.getName(), true);
        WriteObject(ElemNotes, pg.getNotes(), true);
        WriteObject(ElemIcon, pg.getIconId().ordinal());

        if(!pg.getCustomIconUuid().Equals(PwUuid.Zero))
            WriteObject(ElemCustomIconID, pg.getCustomIconUuid());

        WriteList(ElemTimes, pg);
        WriteObject(ElemIsExpanded, pg.isExpanded());
        WriteObject(ElemGroupDefaultAutoTypeSeq, pg.getDefaultAutoTypeSequence(), true);
        WriteObject(ElemEnableAutoType, StrUtil.BoolToStringEx(pg.getEnableAutoType()), false);
        WriteObject(ElemEnableSearching, StrUtil.BoolToStringEx(pg.getEnableSearching()), false);
        WriteObject(ElemLastTopVisibleEntry, pg.getLastTopVisibleEntry());
    }

    private void EndGroup() throws IOException {
        m_xmlWriter.endTag(null, ElemGroup); // Close group element
    }

    private void WriteEntry(PwEntry pe, boolean bIsHistory) throws IOException {
        assert pe != null; if(pe == null) throw new IllegalArgumentException("pe");

        m_xmlWriter.startTag(null, ElemEntry);

        WriteObject(ElemUuid, pe.getUuid());
        WriteObject(ElemIcon, pe.getIconId().ordinal());

        if(!pe.getCustomIconUuid().Equals(PwUuid.Zero))
            WriteObject(ElemCustomIconID, pe.getCustomIconUuid());

        WriteObject(ElemFgColor, StrUtil.ColorToUnnamedHtml(pe.getForegroundColor(), true), false);
        WriteObject(ElemBgColor, StrUtil.ColorToUnnamedHtml(pe.getBackgroundColor(), true), false);
        WriteObject(ElemOverrideUrl, pe.getOverrideUrl(), true);
        WriteObject(ElemTags, StrUtil.TagsToString(pe.getTags(), false), true);

        WriteList(ElemTimes, pe);

        WriteList(pe.getStrings(), true);
        WriteList(pe.getBinaries());
        WriteList(ElemAutoType, pe.getAutoType());

        if(!bIsHistory) WriteList(ElemHistory, pe.getHistory(), true);
        else { assert pe.getHistory().getUCount() == 0; }

        m_xmlWriter.endTag(null, ElemEntry);
    }

    private void WriteList(ProtectedStringDictionary dictStrings, boolean bEntryStrings) throws IOException {
        assert dictStrings != null;
        if(dictStrings == null) throw new IllegalArgumentException("dictStrings");

        for(Map.Entry<String, ProtectedString> kvp : dictStrings)
        WriteObject(kvp.getKey(), kvp.getValue(), bEntryStrings);
    }

    private void WriteList(ProtectedBinaryDictionary dictBinaries) throws IOException {
        assert dictBinaries != null;
        if(dictBinaries == null) throw new IllegalArgumentException("dictBinaries");

        for(Map.Entry<String, ProtectedBinary> kvp : dictBinaries)
        WriteObject(kvp.getKey(), kvp.getValue(), true);
    }

    private void WriteList(String name, AutoTypeConfig cfgAutoType) throws IOException {
        assert name != null;
        assert cfgAutoType != null;
        if(cfgAutoType == null) throw new IllegalArgumentException("cfgAutoType");

        m_xmlWriter.startTag(null, name);

        WriteObject(ElemAutoTypeEnabled, cfgAutoType.isEnabled());
        WriteObject(ElemAutoTypeObfuscation, cfgAutoType.getObfuscationOptions().ordinal());

        if(cfgAutoType.getDefaultSequence().length() > 0)
            WriteObject(ElemAutoTypeDefaultSeq, cfgAutoType.getDefaultSequence(), true);

        for(AutoTypeAssociation a : cfgAutoType.getAssociations())
        WriteObject(ElemAutoTypeItem, ElemWindow, ElemKeystrokeSequence,
                Maps.immutableEntry(a.getWindowName(), a.getSequence()));

        m_xmlWriter.endTag(null, name);
    }

    private void WriteList(String name, ITimeLogger times) throws IOException {
        assert name != null;
        assert times != null; if(times == null) throw new IllegalArgumentException("times");

        m_xmlWriter.startTag(null, name);

        WriteObject(ElemCreationTime, times.getCreationTime());
        WriteObject(ElemLastModTime, times.getLastModificationTime());
        WriteObject(ElemLastAccessTime, times.getLastAccessTime());
        WriteObject(ElemExpiryTime, times.getExpiryTime());
        WriteObject(ElemExpires, times.getExpires());
        WriteObject(ElemUsageCount, times.getUsageCount());
        WriteObject(ElemLocationChanged, times.getLocationChanged());

        m_xmlWriter.endTag(null, name); // Name
    }

    private void WriteList(String name, PwObjectList<PwEntry> value, boolean bIsHistory) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        m_xmlWriter.startTag(null, name);

        for(PwEntry pe : value)
        WriteEntry(pe, bIsHistory);

        m_xmlWriter.endTag(null, name);
    }

    private void WriteList(String name, PwObjectList<PwDeletedObject> value) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        m_xmlWriter.startTag(null, name);

        for(PwDeletedObject pdo : value)
        WriteObject(ElemDeletedObject, pdo);

        m_xmlWriter.endTag(null, name);
    }

    private void WriteList(String name, MemoryProtectionConfig value) throws IOException {
        assert name != null;
        assert value != null;

        m_xmlWriter.startTag(null, name);

        WriteObject(ElemProtTitle, value.ProtectTitle);
        WriteObject(ElemProtUserName, value.ProtectUserName);
        WriteObject(ElemProtPassword, value.ProtectPassword);
        WriteObject(ElemProtUrl, value.ProtectUrl);
        WriteObject(ElemProtNotes, value.ProtectNotes);
        // WriteObject(ElemProtAutoHide, value.AutoEnableVisualHiding);

        m_xmlWriter.endTag(null, name);
    }

    private void WriteList(String name, StringDictionaryEx value) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        m_xmlWriter.startTag(null, name);

        for(Map.Entry<String, String> kvp : value)
        WriteObject(ElemStringDictExItem, ElemKey, ElemValue, kvp);

        m_xmlWriter.endTag(null, name);
    }

    private void WriteCustomIconList() throws IOException {
        if(m_pwDatabase.getCustomIcons().size() == 0) return;

        m_xmlWriter.startTag(null, ElemCustomIcons);

        for(PwCustomIcon pwci : m_pwDatabase.getCustomIcons())
        {
            m_xmlWriter.startTag(null, ElemCustomIconItem);

            WriteObject(ElemCustomIconItemID, pwci.getUuid());

            String strData = BaseEncoding.base64().encode(pwci.getImageDataPng());
            WriteObject(ElemCustomIconItemData, strData, false);

            m_xmlWriter.endTag(null, ElemCustomIconItem);
        }

        m_xmlWriter.endTag(null, ElemCustomIcons);
    }

    private void WriteObject(String name, String value,
                             boolean bFilterValueXmlChars) throws IOException {
        assert name != null;
        assert value != null;

        m_xmlWriter.startTag(null, name);

        if(bFilterValueXmlChars)
            m_xmlWriter.text(StrUtil.SafeXmlString(value));
        else m_xmlWriter.text(value);

        m_xmlWriter.endTag(null, name);
    }

    private void WriteObject(String name, boolean value) throws IOException {
        assert name != null;

        WriteObject(name, value ? ValTrue : ValFalse, false);
    }

    private void WriteObject(String name, PwUuid value) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        WriteObject(name, BaseEncoding.base64().encode(value.getUuidBytes()), false);
    }

    private void WriteObject(String name, int value) throws IOException {
        assert name != null;

        m_xmlWriter.startTag(null, name);
        m_xmlWriter.text(String.valueOf(value));
        m_xmlWriter.endTag(null, name);
    }

    private void WriteObject(String name, long value) throws IOException {
        assert name != null;

        m_xmlWriter.startTag(null, name);
        m_xmlWriter.text(String.valueOf(value));
        m_xmlWriter.endTag(null, name);
    }

    private void WriteObject(String name, Date value) throws IOException {
        assert name != null;

        WriteObject(name, TimeUtil.SerializeUtc(value), false);
    }

    private void WriteObject(String name, String strKeyName,
                             String strValueName, Map.Entry<String, String> kvp) throws IOException {
        m_xmlWriter.startTag(null, name);

        m_xmlWriter.startTag(null, strKeyName);
        m_xmlWriter.text(StrUtil.SafeXmlString(kvp.getKey()));
        m_xmlWriter.endTag(null, strKeyName);
        m_xmlWriter.startTag(null, strValueName);
        m_xmlWriter.text(StrUtil.SafeXmlString(kvp.getValue()));
        m_xmlWriter.endTag(null, strValueName);

        m_xmlWriter.endTag(null, name);
    }

    private void WriteObject(String name, ProtectedString value, boolean bIsEntryString) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        m_xmlWriter.startTag(null, ElemString);
        m_xmlWriter.startTag(null, ElemKey);
        m_xmlWriter.text(StrUtil.SafeXmlString(name));
        m_xmlWriter.endTag(null, ElemKey);
        m_xmlWriter.startTag(null, ElemValue);

        boolean bProtected = value.isProtected();
        if(bIsEntryString)
        {
            // Adjust memory protection setting (which might be different
            // from the database default, e.g. due to an import which
            // didn't specify the correct setting)
            if(PwDefs.TitleField.equals(name))
                bProtected = m_pwDatabase.getMemoryProtection().ProtectTitle;
            else if(PwDefs.UserNameField.equals(name))
                bProtected = m_pwDatabase.getMemoryProtection().ProtectUserName;
            else if(PwDefs.PasswordField.equals(name))
                bProtected = m_pwDatabase.getMemoryProtection().ProtectPassword;
            else if(PwDefs.UrlField.equals(name))
                bProtected = m_pwDatabase.getMemoryProtection().ProtectUrl;
            else if(PwDefs.NotesField.equals(name))
                bProtected = m_pwDatabase.getMemoryProtection().ProtectNotes;
        }

        if(bProtected && (m_format != KdbxFormat.PlainXml))
        {
            m_xmlWriter.attribute(null, AttrProtected, ValTrue);

            byte[] pbEncoded = value.ReadXorredString(m_randomStream);
            if(pbEncoded.length > 0)
                m_xmlWriter.text(BaseEncoding.base64().encode(pbEncoded, 0, pbEncoded.length));
        }
        else
        {
            String strValue = value.ReadString();

            // If names should be localized, we need to apply the language-dependent
            // String transformation here. By default, language-dependent conversions
            // should be applied, otherwise characters could be rendered incorrectly
            // (code page problems).
            if(m_bLocalizedNames)
            {
                StringBuilder sb = new StringBuilder();
                for(char ch : strValue.toCharArray())
                {
                    char chMapped = ch;

                    // Symbols and surrogates must be moved into the correct code
                    // page area
                    /* TODO FIXME is this necessary in java???
                    if(Character.getType(ch) == Character.OTHER_SYMBOL || Character.isSurrogate(ch))
                    {
                        System.Globalization.UnicodeCategory cat =
                                CharUnicodeInfo.GetUnicodeCategory(ch);
                        // Map character to correct position in code page
                        chMapped = (char)((int)cat * 32 + ch);
                    }
                    else if(Character.isISOControl(ch))
                    {
                        if(ch >= 256) // Control character in high ANSI code page
                        {
                            // Some of the control characters map to corresponding ones
                            // in the low ANSI range (up to 255) when calling
                            // ToLower on them with invariant culture (see
                            // http://lists.ximian.com/pipermail/mono-patches/2002-February/086106.html )
                            chMapped = Character.toLowerCase(ch);
                        }
                    }
                    */

                    sb.append(chMapped);
                }

                strValue = sb.toString(); // Correct String for current code page
            }

            if((m_format == KdbxFormat.PlainXml) && bProtected)
                m_xmlWriter.attribute(null, AttrProtectedInMemPlainXml, ValTrue);

            m_xmlWriter.text(StrUtil.SafeXmlString(strValue));
        }

        m_xmlWriter.endTag(null, ElemValue); // ElemValue
        m_xmlWriter.endTag(null, ElemString); // ElemString
    }

    private void WriteObject(String name, ProtectedBinary value, boolean bAllowRef) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        m_xmlWriter.startTag(null, ElemBinary);
        m_xmlWriter.startTag(null, ElemKey);
        m_xmlWriter.text(StrUtil.SafeXmlString(name));
        m_xmlWriter.endTag(null, ElemKey);
        m_xmlWriter.startTag(null, ElemValue);

        String strRef = (bAllowRef ? BinPoolFind(value) : null);
        if(strRef != null)
        {
            m_xmlWriter.attribute(null, AttrRef, strRef);
        }
        else SubWriteValue(value);

        m_xmlWriter.endTag(null, ElemValue); // ElemValue
        m_xmlWriter.endTag(null, ElemBinary); // ElemBinary
    }

    private void SubWriteValue(ProtectedBinary value) throws IOException {
        if(value.isProtected() && (m_format != KdbxFormat.PlainXml))
        {
            m_xmlWriter.attribute(null, AttrProtected, ValTrue);

            byte[] pbEncoded = value.ReadXorredData(m_randomStream);
            if(pbEncoded.length > 0)
                m_xmlWriter.text(BaseEncoding.base64().encode(pbEncoded, 0, pbEncoded.length));
        }
        else
        {
            if(m_pwDatabase.getCompression() == PwCompressionAlgorithm.GZip)
            {
                m_xmlWriter.attribute(null, AttrCompressed, ValTrue);

                byte[] pbRaw = value.ReadData();
                byte[] pbCmp = MemUtil.Compress(pbRaw);
                m_xmlWriter.text(BaseEncoding.base64().encode(pbCmp, 0, pbCmp.length));
            }
            else
            {
                byte[] pbRaw = value.ReadData();
                m_xmlWriter.text(BaseEncoding.base64().encode(pbRaw, 0, pbRaw.length));
            }
        }
    }

    private void WriteObject(String name, PwDeletedObject value) throws IOException {
        assert name != null;
        assert value != null; if(value == null) throw new IllegalArgumentException("value");

        m_xmlWriter.startTag(null, name);
        WriteObject(ElemUuid, value.getUuid());
        WriteObject(ElemDeletionTime, value.getDeletionTime());
        m_xmlWriter.endTag(null, name);
    }

    private void WriteBinPool() throws IOException {
        m_xmlWriter.startTag(null, ElemBinaries);

        for(Map.Entry<String, ProtectedBinary> kvp : m_dictBinPool.entrySet())
        {
            m_xmlWriter.startTag(null, ElemBinary);
            m_xmlWriter.attribute(null, AttrId, kvp.getKey());
            SubWriteValue(kvp.getValue());
            m_xmlWriter.endTag(null, ElemBinary);
        }

        m_xmlWriter.endTag(null, ElemBinaries);
    }

    @Deprecated
    public static boolean WriteEntries(OutputStream msOutput, PwDatabase pwDatabase,
                                    PwEntry[] vEntries) throws IOException {
        return WriteEntries(msOutput, vEntries);
    }

    /// <summary>
    /// Write entries to a stream.
    /// </summary>
    /// <param name="msOutput">Output stream to which the entries will be written.</param>
    /// <param name="vEntries">Entries to serialize.</param>
    /// <returns>Returns <c>true</c>, if the entries were written successfully
    /// to the stream.</returns>
    public static boolean WriteEntries(OutputStream msOutput, PwEntry[] vEntries) throws IOException {
			/* KdbxFile f = new KdbxFile(pwDatabase);
			f.m_format = KdbxFormat.PlainXml;

			XmlTextWriter xtw = null;
			try { xtw = new XmlTextWriter(msOutput, StrUtil.Utf8); }
			catch(Exception) { assert false; return false; }
			if(xtw == null) { assert false; return false; }

			f.m_xmlWriter = xtw;

			xtw.Formatting = Formatting.Indented;
			xtw.IndentChar = '\t';
			xtw.Indentation = 1;

			xtw.WriteStartDocument(true);
			xtw.WriteStartElement(ElemRoot);

			for(PwEntry pe : vEntries)
				f.WriteEntry(pe, false);

			xtw.WriteEndElement();
			xtw.WriteEndDocument();

			xtw.Flush();
			xtw.Close();
			return true; */

        PwDatabase pd = new PwDatabase();
        pd.New(new IOConnectionInfo(), new CompositeKey());

        for(PwEntry peCopy : vEntries)
        pd.getRootGroup().AddEntry(peCopy.CloneDeep(), true);

        KdbxFile f = new KdbxFile(pd);
        f.Save(msOutput, null, KdbxFormat.PlainXml, null);
        return true;
    }

        public static MessageDigest sha256() {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
}
