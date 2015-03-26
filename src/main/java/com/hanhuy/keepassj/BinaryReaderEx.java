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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

public class BinaryReaderEx
	{
		private InputStream m_s;
		// private Encoding m_enc; // See constructor

		private String m_strReadExcp;
		public String getReadExceptionText()
		{
			return m_strReadExcp;
		}
        public void setReadExceptionText(String value) { m_strReadExcp = value; }

		private OutputStream m_sCopyTo = null;
		/// <summary>
		/// If this property is set to a non-null stream, all data that
		/// is read from the input stream is automatically written to
		/// the copy stream (before returning the read data).
		/// </summary>
		public OutputStream getCopyDataTo()
		{
			return m_sCopyTo;
		}
        public void setCopyDataTo(OutputStream value) { m_sCopyTo = value; }

		public BinaryReaderEx(InputStream input, Charset encoding,
			String strReadExceptionText)
		{
			if(input == null) throw new IllegalArgumentException("input");

			m_s = input;
			// m_enc = encoding; // Not used yet
			m_strReadExcp = strReadExceptionText;
		}

		public byte[] ReadBytes(int nCount) throws IOException
		{
			try
			{
				byte[] pb = MemUtil.Read(m_s, nCount);
				if((pb == null) || (pb.length != nCount))
				{
					if(m_strReadExcp != null) throw new IOException(m_strReadExcp);
					else throw new EOFException();
				}

				if(m_sCopyTo != null) m_sCopyTo.write(pb, 0, pb.length);
				return pb;
			}
			catch(Exception e)
			{
				if(m_strReadExcp != null) throw new IOException(m_strReadExcp, e);
				else throw new RuntimeException(e);
			}
		}

		public byte ReadByte() throws IOException
		{
			byte[] pb = ReadBytes(1);
			return pb[0];
		}
	}
