package com.hanhuy.keepassj.spr;
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
	class SprEncoding
	{
		static String MakeAutoTypeSequence(String str)
		{
			if(str == null) { assert false; return ""; }

			str = SprEncoding.EscapeAutoTypeBrackets(str);

			str = str.replace("[", "{[}");
			str = str.replace("]", "{]}");

			str = str.replace("+", "{+}");
			str = str.replace("%", "{%}");
			str = str.replace("~", "{~}");
			str = str.replace("(", "{(}");
			str = str.replace(")", "{)}");

			str = str.replace("^", "{^}");

			return str;
		}

		private static String EscapeAutoTypeBrackets(String str)
		{
			char chOpen = '\u25A1';
			while(str.indexOf(chOpen) >= 0) ++chOpen;

			char chClose = chOpen;
			++chClose;
			while(str.indexOf(chClose) >= 0) ++chClose;

			str = str.replace('{', chOpen);
			str = str.replace('}', chClose);

			str = str.replace(String.valueOf(chOpen), "{{}");
			str = str.replace(String.valueOf(chClose), "{}}");

			return str;
		}

		static String MakeCommandQuotes(String str)
		{
			if(str == null) { assert false; return ""; }

			// See SHELLEXECUTEINFO structure documentation
			return str.replace("\"", "\"\"\"");
		}
	}
