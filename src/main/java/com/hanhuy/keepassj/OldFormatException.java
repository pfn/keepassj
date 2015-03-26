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

	public class OldFormatException extends RuntimeException
	{
		private String m_strFormat = "";
		private OldFormatType m_type = OldFormatType.Unknown;

		public enum OldFormatType
		{
			Unknown,
			KeePass1x
		}

		public String getMessage()
		{
				String str = ((m_strFormat.length() > 0) ?
					(" (" + m_strFormat + ")") : "") + ".";

				if(m_type == OldFormatType.KeePass1x)
					str += "\n"+ "keepass1hint";

				return str;
		}

		public OldFormatException(String strFormatName)
		{
            super();
			if(strFormatName != null) m_strFormat = strFormatName;
		}

		public OldFormatException(String strFormatName, OldFormatType t)
		{
            super();
			if(strFormatName != null) m_strFormat = strFormatName;

			m_type = t;
		}
	}
