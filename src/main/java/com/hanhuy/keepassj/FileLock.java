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

import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import scala.Int;
import scala.util.parsing.input.StreamReader;

import java.io.*;
import java.util.Date;

class FileLockException extends RuntimeException
	{
		private final String m_strMsg;

        @Override
		public String getMessage()
		{
			return m_strMsg;
		}

		public FileLockException(String strBaseFile, String strUser)
		{
			StringBuilder sb = new StringBuilder();

			if(!Strings.isNullOrEmpty(strBaseFile))
			{
				sb.append(strBaseFile);
				sb.append("\n");
			}

			sb.append("file locked for writing");
			sb.append("\n");

			if(!Strings.isNullOrEmpty(strUser)) sb.append(strUser);
			else sb.append("?");

			sb.append("\n");
			sb.append("try again in a few seconds");

			m_strMsg = sb.toString();
		}
	}

	class FileLock implements Closeable
	{
		private final static String LockFileExt = ".lock";
		private final static String LockFileHeader = "KeePass Lock File";

		private IOConnectionInfo m_iocLockFile;

		private static class LockFileInfo
		{
			public final String ID;
			public final Date Time;
			public final String UserName;
			public final String Machine;
			public final String Domain;

			private LockFileInfo(String strID, String strTime, String strUserName,
				String strMachine, String strDomain)
			{
				this.ID = Strings.nullToEmpty(strID).trim();

				Date[] dt = new Date[1];
				if(TimeUtil.TryDeserializeUtc(strTime.trim(), dt))
					this.Time = dt[0];
				else
				{
					assert false;
					this.Time = new Date();
				}

				this.UserName = Strings.nullToEmpty(strUserName).trim();
				this.Machine = Strings.nullToEmpty(strMachine).trim();
				String _Domain = Strings.nullToEmpty(strDomain).trim();

				if(_Domain.equalsIgnoreCase(this.Machine))
					_Domain = "";
                this.Domain = _Domain;
			}

			public String GetOwner()
			{
				StringBuilder sb = new StringBuilder();
				sb.append((this.UserName.length() > 0) ? this.UserName : "?");

				boolean bMachine = (this.Machine.length() > 0);
				boolean bDomain = (this.Domain.length() > 0);
				if(bMachine || bDomain)
				{
					sb.append(" (");
					sb.append(this.Machine);
					if(bMachine && bDomain) sb.append(" @ ");
					sb.append(this.Domain);
					sb.append(")");
				}

				return sb.toString();
			}

			public static LockFileInfo Load(IOConnectionInfo iocLockFile) {
				InputStream s = null;
				try
				{
					s = IOConnection.OpenRead(iocLockFile);
					if(s == null) return null;
					InputStreamReader sr = new InputStreamReader(s, StrUtil.Utf8);
                    StringWriter sw = new StringWriter();
                    char[] buf = new char[8192];
                    int read;
                    while ((read = sr.read(buf, 0, 8192)) != -1)
                        sw.write(buf, 0, read);
					sr.close();
                    String str = sw.toString();
					if(str == null) { assert false; return null; }

					str = StrUtil.NormalizeNewLines(str, false);
					String[] v = str.split("\n");
					if((v == null) || (v.length < 6)) { assert false; return null; }

					if(!v[0].startsWith(LockFileHeader)) { assert false; return null; }
					return new LockFileInfo(v[1], v[2], v[3], v[4], v[5]);
				}
				catch(Exception e) { }
				finally { if(s != null) try {
                    s.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                }

				return null;
			}

			// Throws on error
			public static LockFileInfo Create(IOConnectionInfo iocLockFile) throws IOException {
				LockFileInfo lfi;
				OutputStream s = null;
				try
				{
					byte[] pbID = CryptoRandom.getInstance().GetRandomBytes(16);
					String strTime = TimeUtil.SerializeUtc(new Date());

					lfi = new LockFileInfo(BaseEncoding.base64().encode(pbID), strTime,
						System.getProperty("user.name"), System.getProperty("os.name"),
						System.getProperty("os.version"));

					StringBuilder sb = new StringBuilder();
					sb.append(LockFileHeader + "\n");
					sb.append(lfi.ID + "\n");
					sb.append(strTime + "\n");
					sb.append(lfi.UserName + "\n");
					sb.append(lfi.Machine + "\n");
					sb.append(lfi.Domain + "\n");

					byte[] pbFile = sb.toString().getBytes("utf-8");

					s = IOConnection.OpenWrite(iocLockFile);
					if(s == null) throw new IOException(iocLockFile.GetDisplayName());
					s.write(pbFile, 0, pbFile.length);
				}
				finally { if(s != null) s.close(); }

				return lfi;
			}
		}

		public FileLock(IOConnectionInfo iocBaseFile) throws IOException {
			if(iocBaseFile == null) throw new IllegalArgumentException("strBaseFile");

			m_iocLockFile = iocBaseFile.CloneDeep();
			m_iocLockFile.setPath(m_iocLockFile.getPath() + LockFileExt);

			LockFileInfo lfiEx = LockFileInfo.Load(m_iocLockFile);
			if(lfiEx != null)
			{
				m_iocLockFile = null; // Otherwise Dispose deletes the existing one
				throw new FileLockException(iocBaseFile.GetDisplayName(),
					lfiEx.GetOwner());
			}

			LockFileInfo.Create(m_iocLockFile);
		}

		public void close()
		{
			if(m_iocLockFile == null) return;

			boolean bFileDeleted = false;
			for(int r = 0; r < 5; ++r)
			{
				// if(!OwnLockFile()) { bFileDeleted = true; break; }

					bFileDeleted = IOConnection.DeleteFile(m_iocLockFile);

				if(bFileDeleted) break;

                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                }
			}

			if(!bFileDeleted)
				IOConnection.DeleteFile(m_iocLockFile); // Possibly with exception

			m_iocLockFile = null;
		}

		// private boolean OwnLockFile()
		// {
		//	if(m_iocLockFile == null) { assert false; return false; }
		//	if(m_strLockID == null) { assert false; return false; }
		//	LockFileInfo lfi = LockFileInfo.Load(m_iocLockFile);
		//	if(lfi == null) return false;
		//	return m_strLockID.Equals(lfi.ID);
		// }
	}
