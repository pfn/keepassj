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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;

public class FileTransactionEx
	{
		private boolean m_bTransacted;
		private IOConnectionInfo m_iocBase;
		private IOConnectionInfo m_iocTemp;

		private boolean m_bMadeUnhidden = false;

		private final static String StrTempSuffix = ".tmp";

		private static boolean g_bExtraSafe = false;
		public void setExtraSafe(boolean b) {
			g_bExtraSafe = b;
		}
		public boolean isExtraSafe() { return g_bExtraSafe; }

		public FileTransactionEx(IOConnectionInfo iocBaseFile)
		{
			Initialize(iocBaseFile, true);
		}

		public FileTransactionEx(IOConnectionInfo iocBaseFile, boolean bTransacted)
		{
			Initialize(iocBaseFile, bTransacted);
		}

		private void Initialize(IOConnectionInfo iocBaseFile, boolean bTransacted)
		{
			if(iocBaseFile == null) throw new IllegalArgumentException("iocBaseFile");

			m_bTransacted = bTransacted;
			m_iocBase = iocBaseFile.CloneDeep();

			if(m_bTransacted)
			{
				m_iocTemp = m_iocBase.CloneDeep();
				m_iocTemp.setPath(m_iocTemp.getPath() + StrTempSuffix);
			}
			else m_iocTemp = m_iocBase;
		}

		public OutputStream OpenWrite() throws IOException {
			if(!m_bTransacted) m_bMadeUnhidden = UrlUtil.UnhideFile(m_iocTemp.getPath());
			else // m_bTransacted
			{
				try { IOConnection.DeleteFile(m_iocTemp); }
				catch(Exception e) { }
			}

			return IOConnection.OpenWrite(m_iocTemp);
		}

		public void CommitWrite() throws IOException
		{
			if(m_bTransacted) CommitWriteTransaction();
			else // !m_bTransacted
			{
				if(m_bMadeUnhidden) UrlUtil.HideFile(m_iocTemp.getPath(), true); // Hide again
			}
		}

		private void CommitWriteTransaction() throws IOException
		{
			boolean bMadeUnhidden = UrlUtil.UnhideFile(m_iocBase.getPath());


			if (g_bExtraSafe)
			{
				if(!IOConnection.FileExists(m_iocTemp))
					throw new FileNotFoundException(m_iocTemp.getPath() + ": file save failed");
			}
			if(IOConnection.FileExists(m_iocBase))
			{
				IOConnection.DeleteFile(m_iocBase);
			}

			IOConnection.RenameFile(m_iocTemp, m_iocBase);

			if(bMadeUnhidden) UrlUtil.HideFile(m_iocBase.getPath(), true); // Hide again
		}
	}
