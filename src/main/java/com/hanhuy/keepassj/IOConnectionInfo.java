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

import java.io.File;

enum IOCredSaveMode
	{
		/// <summary>
		/// Do not remember user name or password.
		/// </summary>
		NoSave,

		/// <summary>
		/// Remember the user name only, not the password.
		/// </summary>
		UserNameOnly,

		/// <summary>
		/// Save both user name and password.
		/// </summary>
		SaveCred
	}

	enum IOCredProtMode
	{
		None,
		Obf
	}

	/* public enum IOFileFormatHint
	{
		None = 0,
		Deprecated
	} */

	public class IOConnectionInfo implements IDeepCloneable<IOConnectionInfo>, Cloneable
	{
		// private IOFileFormatHint m_ioHint = IOFileFormatHint.None;

		private String m_strUrl = "";
		public String getPath()
		{
			return m_strUrl;
		}
        public void setPath(String value)
        {
            assert value != null;
            if(value == null) throw new IllegalArgumentException("value");

            m_strUrl = value;
        }

		private String m_strUser = "";
		//[DefaultValue("")]
		public String getUserName()
		{
			return m_strUser;
		}
        public void setUserName(String value)
        {
            assert value != null;
            if(value == null) throw new IllegalArgumentException("value");

            m_strUser = value;
        }

		private String m_strPassword = "";
//		[DefaultValue("")]
		public String getPassword()
		{
			return m_strPassword;
		}
        public void setPassword(String value)
        {
            assert value != null;
            if(value == null) throw new IllegalArgumentException("value");

            m_strPassword = value;
        }

		private IOCredProtMode m_ioCredProtMode = IOCredProtMode.None;
		public IOCredProtMode getCredProtMode()
		{
			return m_ioCredProtMode;
		}
        public void setCredProtMode(IOCredProtMode value) { m_ioCredProtMode = value; }

		private IOCredSaveMode m_ioCredSaveMode = IOCredSaveMode.NoSave;
		public IOCredSaveMode getCredSaveMode()
		{
			return m_ioCredSaveMode;
		}
        public void setCredSaveMode(IOCredSaveMode value) { m_ioCredSaveMode = value; }

		private boolean m_bComplete = false;
//		[XmlIgnore]
		public boolean isComplete() // Credentials etc. fully specified
		{
			return m_bComplete;
		}
        public void setComplete(boolean value) { m_bComplete = value; }

		/* public IOFileFormatHint FileFormatHint
		{
			get { return m_ioHint; }
			set { m_ioHint = value; }
		} */

		// INTENTIONALLY DON'T CARE ABOUT IocProperties*

		public IOConnectionInfo CloneDeep()
		{
            try {
                return (IOConnectionInfo) clone();
            } catch (Exception e) { throw new RuntimeException(e); }
		}

		public String toString()
		{
			return GetDisplayName();
		}

		/*
		/// <summary>
		/// Serialize the current connection info to a String. Credentials
		/// are serialized based on the <c>CredSaveMode</c> property.
		/// </summary>
		/// <param name="iocToCompile">Input object to be serialized.</param>
		/// <returns>Serialized object as String.</returns>
		public static String SerializeToString(IOConnectionInfo iocToCompile)
		{
			assert iocToCompile != null;
			if(iocToCompile == null) throw new IllegalArgumentException("iocToCompile");

			String strUrl = iocToCompile.Path;
			String strUser = TransformUnreadable(iocToCompile.UserName, true);
			String strPassword = TransformUnreadable(iocToCompile.Password, true);

			String strAll = strUrl + strUser + strPassword + "CUN";
			char chSep = StrUtil.GetUnusedChar(strAll);
			if(chSep == char.MinValue) throw new FormatException();

			StringBuilder sb = new StringBuilder();
			sb.Append(chSep);
			sb.Append(strUrl);
			sb.Append(chSep);

			if(iocToCompile.CredSaveMode == IOCredSaveMode.SaveCred)
			{
				sb.Append('C');
				sb.Append(chSep);
				sb.Append(strUser);
				sb.Append(chSep);
				sb.Append(strPassword);
			}
			else if(iocToCompile.CredSaveMode == IOCredSaveMode.UserNameOnly)
			{
				sb.Append('U');
				sb.Append(chSep);
				sb.Append(strUser);
				sb.Append(chSep);
			}
			else // Don't remember credentials
			{
				sb.Append('N');
				sb.Append(chSep);
				sb.Append(chSep);
			}

			return sb.ToString();
		}

		public static IOConnectionInfo UnserializeFromString(String strToDecompile)
		{
			assert strToDecompile != null;
			if(strToDecompile == null) throw new IllegalArgumentException("strToDecompile");
			if(strToDecompile.Length <= 1) throw new ArgumentException();

			char chSep = strToDecompile[0];
			String[] vParts = strToDecompile.Substring(1, strToDecompile.Length -
				1).Split(new char[]{ chSep });
			if(vParts.Length < 4) throw new ArgumentException();

			IOConnectionInfo s = new IOConnectionInfo();
			s.Path = vParts[0];

			if(vParts[1] == "C")
				s.CredSaveMode = IOCredSaveMode.SaveCred;
			else if(vParts[1] == "U")
				s.CredSaveMode = IOCredSaveMode.UserNameOnly;
			else
				s.CredSaveMode = IOCredSaveMode.NoSave;

			s.UserName = TransformUnreadable(vParts[2], false);
			s.Password = TransformUnreadable(vParts[3], false);
			return s;
		}
		*/

		/*
		/// <summary>
		/// Very simple String protection. Doesn't really encrypt the input
		/// String, only encodes it that it's not readable on the first glance.
		/// </summary>
		/// <param name="strToEncode">The String to encode/decode.</param>
		/// <param name="bEncode">If <c>true</c>, the String will be encoded,
		/// otherwise it'll be decoded.</param>
		/// <returns>Encoded/decoded String.</returns>
		private static String TransformUnreadable(String strToEncode, boolean bEncode)
		{
			assert strToEncode != null;
			if(strToEncode == null) throw new IllegalArgumentException("strToEncode");

			if(bEncode)
			{
				byte[] pbUtf8 = StrUtil.Utf8.GetBytes(strToEncode);

				unchecked
				{
					for(int iPos = 0; iPos < pbUtf8.Length; ++iPos)
						pbUtf8[iPos] += (byte)(iPos * 11);
				}

				return Convert.ToBase64String(pbUtf8);
			}
			else // Decode
			{
				byte[] pbBase = Convert.FromBase64String(strToEncode);

				unchecked
				{
					for(int iPos = 0; iPos < pbBase.Length; ++iPos)
						pbBase[iPos] -= (byte)(iPos * 11);
				}

				return StrUtil.Utf8.GetString(pbBase, 0, pbBase.Length);
			}
		}
		*/

		public String GetDisplayName()
		{
			String str = m_strUrl;

			if(m_strUser.length() > 0)
				str += " (" + m_strUser + ")";

			return str;
		}

		public boolean IsEmpty()
		{
			return (m_strUrl.length() == 0);
		}

		public static IOConnectionInfo FromPath(String strPath)
		{
			IOConnectionInfo ioc = new IOConnectionInfo();

			ioc.setPath(strPath);
			ioc.setCredSaveMode(IOCredSaveMode.NoSave);

			return ioc;
		}

		public boolean CanProbablyAccess()
		{
			if(IsLocalFile()) return (new File(m_strUrl).exists());

			return true;
		}

		public boolean IsLocalFile()
		{
			// Not just ":/", see e.g. AppConfigEx.ChangePathRelAbs
			return (m_strUrl.indexOf("://") < 0);
		}

		public void ClearCredentials(boolean bDependingOnRememberMode)
		{
			if((!bDependingOnRememberMode) ||
				(m_ioCredSaveMode == IOCredSaveMode.NoSave))
			{
				m_strUser = "";
			}

			if((!bDependingOnRememberMode) ||
				(m_ioCredSaveMode == IOCredSaveMode.NoSave) ||
				(m_ioCredSaveMode == IOCredSaveMode.UserNameOnly))
			{
				m_strPassword = "";
			}
		}

		public void Obfuscate(boolean bObf)
		{
			if(bObf && (m_ioCredProtMode == IOCredProtMode.None))
			{
				m_strPassword = StrUtil.Obfuscate(m_strPassword);
				m_ioCredProtMode = IOCredProtMode.Obf;
			}
			else if(!bObf && (m_ioCredProtMode == IOCredProtMode.Obf))
			{
				m_strPassword = StrUtil.Deobfuscate(m_strPassword);
				m_ioCredProtMode = IOCredProtMode.None;
			}
		}
	}
