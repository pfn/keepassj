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

import com.google.common.io.BaseEncoding;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import org.xmlpull.v1.XmlSerializer;

import java.io.*;

/// <summary>
	/// Key files as provided by the user.
	/// </summary>
	public class KcpKeyFile implements IUserKey
	{
		private String m_strPath;
		private ProtectedBinary m_pbKeyData;

		/// <summary>
		/// Path to the key file.
		/// </summary>
		public String getPath()
		{
			return m_strPath;
		}

		/// <summary>
		/// Get key data. Querying this property is fast (it returns a
		/// reference to a cached <c>ProtectedBinary</c> object).
		/// If no key data is available, <c>null</c> is returned.
		/// </summary>
		public ProtectedBinary getKeyData()
		{
			return m_pbKeyData;
		}

		public KcpKeyFile(String strKeyFile) throws IOException {
			Construct(IOConnectionInfo.FromPath(strKeyFile), false);
		}

		public KcpKeyFile(String strKeyFile, boolean bThrowIfDbFile) throws IOException {
			Construct(IOConnectionInfo.FromPath(strKeyFile), bThrowIfDbFile);
		}

		public KcpKeyFile(IOConnectionInfo iocKeyFile) throws IOException {
			Construct(iocKeyFile, false);
		}

		public KcpKeyFile(IOConnectionInfo iocKeyFile, boolean bThrowIfDbFile) throws IOException {
			Construct(iocKeyFile, bThrowIfDbFile);
		}

		private void Construct(IOConnectionInfo iocFile, boolean bThrowIfDbFile)
                throws IOException
		{
			byte[] pbFileData = IOConnection.ReadFile(iocFile);
			if(pbFileData == null) throw new FileNotFoundException();

			if(bThrowIfDbFile && (pbFileData.length >= 8))
			{
				int uSig1 = MemUtil.BytesToUInt32(MemUtil.Mid(pbFileData, 0, 4));
				int uSig2 = MemUtil.BytesToUInt32(MemUtil.Mid(pbFileData, 4, 4));

				if(((uSig1 == KdbxFile.FileSignature1) &&
					(uSig2 == KdbxFile.FileSignature2)) ||
					((uSig1 == KdbxFile.FileSignaturePreRelease1) &&
					(uSig2 == KdbxFile.FileSignaturePreRelease2)) ||
					((uSig1 == KdbxFile.FileSignatureOld1) &&
					(uSig2 == KdbxFile.FileSignatureOld2)))
					throw new KdbxFileFormatException("bad key file");
			}

			byte[] pbKey = LoadXmlKeyFile(pbFileData);
			if(pbKey == null) pbKey = LoadKeyFile(pbFileData);

			if(pbKey == null) throw new UnsupportedOperationException();

			m_strPath = iocFile.getPath();
			m_pbKeyData = new ProtectedBinary(true, pbKey);

			MemUtil.ZeroByteArray(pbKey);
		}

		// public void Clear()
		// {
		//	m_strPath = String.Empty;
		//	m_pbKeyData = null;
		// }

		private static byte[] LoadKeyFile(byte[] pbFileData)
		{
			if(pbFileData == null) { assert false; return null; }

			int iLength = pbFileData.length;

			byte[] pbKey = null;
			if(iLength == 32) pbKey = LoadBinaryKey32(pbFileData);
			else if(iLength == 64) pbKey = LoadHexKey32(pbFileData);

			if(pbKey == null)
			{
				pbKey = Digests.sha256(pbFileData);
			}

			return pbKey;
		}

		private static byte[] LoadBinaryKey32(byte[] pbFileData)
		{
			if(pbFileData == null) { assert false; return null; }
			if(pbFileData.length != 32) { assert false; return null; }

			return pbFileData;
		}

		private static byte[] LoadHexKey32(byte[] pbFileData)
		{
			if(pbFileData == null) { assert false; return null; }
			if(pbFileData.length != 64) { assert false; return null; }

			try
			{
				String strHex = new String(pbFileData, 0, 64, StrUtil.Utf8);
				if(!StrUtil.IsHexString(strHex, true)) return null;

				byte[] pbKey = MemUtil.HexStringToByteArray(strHex);
				if((pbKey == null) || (pbKey.length != 32))
					return null;

				return pbKey;
			}
			catch(Exception e) { throw new RuntimeException(e); }
		}

		/// <summary>
		/// Create a new, random key-file.
		/// </summary>
		/// <param name="strFilePath">Path where the key-file should be saved to.
		/// If the file exists already, it will be overwritten.</param>
		/// <param name="pbAdditionalEntropy">Additional entropy used to generate
		/// the random key. May be <c>null</c> (in this case only the KeePass-internal
		/// random number generator is used).</param>
		/// <returns>Returns a <c>FileSaveResult</c> error code.</returns>
		public static void Create(String strFilePath, byte[] pbAdditionalEntropy) throws IOException, XmlPullParserException {
			byte[] pbKey32 = CryptoRandom.getInstance().GetRandomBytes(32);
			if(pbKey32 == null) throw new SecurityException();

			byte[] pbFinalKey32;
			if((pbAdditionalEntropy == null) || (pbAdditionalEntropy.length == 0))
				pbFinalKey32 = pbKey32;
			else
			{
				ByteArrayOutputStream ms = new ByteArrayOutputStream();
				ms.write(pbAdditionalEntropy, 0, pbAdditionalEntropy.length);
				ms.write(pbKey32, 0, 32);

				pbFinalKey32 = Digests.sha256(ms.toByteArray());
			}

			CreateXmlKeyFile(strFilePath, pbFinalKey32);
		}

		// ================================================================
		// XML Key Files
		// ================================================================

		// Sample XML file:
		// <?xml version="1.0" encoding="utf-8"?>
		// <KeyFile>
		//     <Meta>
		//         <Version>1.00</Version>
		//     </Meta>
		//     <Key>
		//         <Data>ySFoKuCcJblw8ie6RkMBdVCnAf4EedSch7ItujK6bmI=</Data>
		//     </Key>
		// </KeyFile>

		private final static String RootElementName = "KeyFile";
		private final static String MetaElementName = "Meta";
		private final static String VersionElementName = "Version";
		private final static String KeyElementName = "Key";
		private final static String KeyDataElementName = "Data";

		private static byte[] LoadXmlKeyFile(byte[] pbFileData)
		{
			if(pbFileData == null) { assert false; return null; }

			ByteArrayInputStream ms = new ByteArrayInputStream(pbFileData);
			byte[] pbKeyData = null;

			try
			{
                XmlPullParserFactory fact = XmlPullParserFactory.newInstance();
                XmlPullParser parser = fact.newPullParser();
                parser.setInput(ms, "utf-8");

                String[] tree = {
                        RootElementName,
                        MetaElementName,
                        VersionElementName,
                        KeyElementName,
                        KeyDataElementName
                };

                int depth = 0;
                while (parser.next() != XmlPullParser.END_DOCUMENT && depth < tree.length) {
                    if (parser.getEventType() == XmlPullParser.START_TAG) {
                        if (tree[depth].equals(parser.getName())) {
                            depth++;
                        }
                        if (KeyDataElementName.equals(parser.getName()))
                            pbKeyData = BaseEncoding.base64().decode(parser.nextText());
                    }
                }

			}
			catch(Exception e) { pbKeyData = null; }

			return pbKeyData;
		}

		private static void CreateXmlKeyFile(String strFile, byte[] pbKeyData) throws IOException, XmlPullParserException {
			assert strFile != null;
			if(strFile == null) throw new IllegalArgumentException("strFile");
			assert pbKeyData != null;
			if(pbKeyData == null) throw new IllegalArgumentException("pbKeyData");

			IOConnectionInfo ioc = IOConnectionInfo.FromPath(strFile);
			OutputStream sOut = IOConnection.OpenWrite(ioc);

            XmlPullParserFactory fact = XmlPullParserFactory.newInstance();
			XmlSerializer xtw = fact.newSerializer();
            xtw.setOutput(sOut, "utf-8");

			xtw.startDocument("utf-8", true);
			xtw.startTag(null, RootElementName); // KeyFile

			xtw.startTag(null, MetaElementName); // Meta
			xtw.startTag(null, VersionElementName); // Version
			xtw.text("1.00");
			xtw.endTag(null, VersionElementName); // End Version
			xtw.endTag(null, MetaElementName); // End Meta

			xtw.startTag(null, KeyElementName); // Key

			xtw.startTag(null, KeyDataElementName); // Data
			xtw.text(BaseEncoding.base64().encode(pbKeyData));
			xtw.endTag(null, KeyDataElementName); // End Data
			xtw.endTag(null, KeyElementName); // End Key

			xtw.endTag(null, RootElementName); // RootElementName
			xtw.endDocument(); // End KeyFile

			sOut.close();
		}
	}
