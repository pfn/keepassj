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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.EventObject;

	/// <summary>
	/// Contains KeePassLib-global definitions and enums.
	/// </summary>
	public class PwDefs
	{
		/// <summary>
		/// The product name.
		/// </summary>
		public final static String ProductName = "KeePass Password Safe";

		/// <summary>
		/// A short, simple String representing the product name. The String
		/// should contain no spaces, directory separator characters, etc.
		/// </summary>
		public final static String ShortProductName = "KeePass";

		final String UnixName = "keepass2";
		final String ResClass = "KeePass2"; // With initial capital

		/// <summary>
		/// Version, encoded as 32-bit unsigned integer.
		/// 2.00 = 0x02000000, 2.01 = 0x02000100, ..., 2.18 = 0x02010800.
		/// As of 2.19, the version is encoded component-wise per byte,
		/// e.g. 2.19 = 0x02130000.
		/// It is highly recommended to use <c>FileVersion64</c> instead.
		/// </summary>
		public final static int Version32 = 0x021D0000;

		/// <summary>
		/// Version, encoded as 64-bit unsigned integer
		/// (component-wise, 16 bits per component).
		/// </summary>
		public final static long FileVersion64 = 0x0002001D00000000L;

		/// <summary>
		/// Version, encoded as String.
		/// </summary>
		public final static String VersionString = "2.29";

		public final static String Copyright = "Copyright © 2003-2014 Dominik Reichl";

		/// <summary>
		/// Product website URL. Terminated by a forward slash.
		/// </summary>
		public final static String HomepageUrl = "http://keepass.info/";

		/// <summary>
		/// Product donations URL.
		/// </summary>
		public final static String DonationsUrl = "http://keepass.info/donate.html";

		/// <summary>
		/// URL to the online plugins page.
		/// </summary>
		public final static String PluginsUrl = "http://keepass.info/plugins.html";

		/// <summary>
		/// URL to the online translations page.
		/// </summary>
		public final static String TranslationsUrl = "http://keepass.info/translations.html";

		/// <summary>
		/// URL to a TXT file (eventually compressed) that contains information
		/// about the latest KeePass version available on the website.
		/// </summary>
		public final static String VersionUrl = "http://keepass.info/update/version2x.txt.gz";

		/// <summary>
		/// URL to the root path of the online KeePass help. Terminated by
		/// a forward slash.
		/// </summary>
		public final static String HelpUrl = "http://keepass.info/help/";

		/// <summary>
		/// A <c>Date</c> Object that represents the time when the assembly
		/// was loaded.
		/// </summary>
		public static final Date DtDefaultNow = new Date();

		/// <summary>
		/// Default number of master key encryption/transformation rounds (making dictionary attacks harder).
		/// </summary>
		public final static long DefaultKeyEncryptionRounds = 6000;

		/// <summary>
		/// Default identifier String for the title field. Should not contain
		/// spaces, tabs or other whitespace.
		/// </summary>
		public final static String TitleField = "Title";

		/// <summary>
		/// Default identifier String for the user name field. Should not contain
		/// spaces, tabs or other whitespace.
		/// </summary>
		public final static String UserNameField = "UserName";

		/// <summary>
		/// Default identifier String for the password field. Should not contain
		/// spaces, tabs or other whitespace.
		/// </summary>
		public final static String PasswordField = "Password";

		/// <summary>
		/// Default identifier String for the URL field. Should not contain
		/// spaces, tabs or other whitespace.
		/// </summary>
		public final static String UrlField = "URL";

		/// <summary>
		/// Default identifier String for the notes field. Should not contain
		/// spaces, tabs or other whitespace.
		/// </summary>
		public final static String NotesField = "Notes";

		/// <summary>
		/// Default identifier String for the field which will contain TAN indices.
		/// </summary>
		public final static String TanIndexField = UserNameField;

		/// <summary>
		/// Default title of an entry that is really a TAN entry.
		/// </summary>
		public final static String TanTitle = "<TAN>";

		/// <summary>
		/// Prefix of a custom auto-type String field.
		/// </summary>
		public final static String AutoTypeStringPrefix = "S:";

		/// <summary>
		/// Default String representing a hidden password.
		/// </summary>
		public final static String HiddenPassword = "********";

		/// <summary>
		/// Default auto-type keystroke sequence. If no custom sequence is
		/// specified, this sequence is used.
		/// </summary>
		public final static String DefaultAutoTypeSequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

		/// <summary>
		/// Default auto-type keystroke sequence for TAN entries. If no custom
		/// sequence is specified, this sequence is used.
		/// </summary>
		public final static String DefaultAutoTypeSequenceTan = "{PASSWORD}";

		/// <summary>
		/// Check if a name is a standard field name.
		/// </summary>
		/// <param name="strFieldName">Input field name.</param>
		/// <returns>Returns <c>true</c>, if the field name is a standard
		/// field name (title, user name, password, ...), otherwise <c>false</c>.</returns>
		public static boolean IsStandardField(String strFieldName)
		{
			assert strFieldName != null; if(strFieldName == null) return false;

			if(strFieldName.equals(TitleField)) return true;
			if(strFieldName.equals(UserNameField)) return true;
			if(strFieldName.equals(PasswordField)) return true;
			if(strFieldName.equals(UrlField)) return true;
			if(strFieldName.equals(NotesField)) return true;

			return false;
		}

		public static List<String> GetStandardFields()
		{
			List<String> l = new ArrayList<String>();

			l.add(TitleField);
			l.add(UserNameField);
			l.add(PasswordField);
			l.add(UrlField);
			l.add(NotesField);

			return l;
		}

		/// <summary>
		/// Check if an entry is a TAN.
		/// </summary>
		/// <param name="pe">Password entry.</param>
		/// <returns>Returns <c>true</c> if the entry is a TAN.</returns>
		public static boolean IsTanEntry(PwEntry pe)
		{
			assert pe != null; if(pe == null) return false;

			return (pe.getStrings().ReadSafe(PwDefs.TitleField).equals(TanTitle));
		}
	}


	// #pragma warning disable 1591 // Missing XML comments warning
	/// <summary>
	/// Memory protection configuration structure (for default fields).
	/// </summary>
	class MemoryProtectionConfig implements IDeepCloneable<MemoryProtectionConfig>, Cloneable
	{
		public boolean ProtectTitle = false;
		public boolean ProtectUserName = false;
		public boolean ProtectPassword = true;
		public boolean ProtectUrl = false;
		public boolean ProtectNotes = false;

		// public boolean AutoEnableVisualHiding = false;

		public MemoryProtectionConfig CloneDeep()
		{
            try {
                return (MemoryProtectionConfig) clone();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
		}

		public boolean GetProtection(String strField)
		{
			if(strField.equals(PwDefs.TitleField)) return this.ProtectTitle;
			if(strField.equals(PwDefs.UserNameField)) return this.ProtectUserName;
			if(strField.equals(PwDefs.PasswordField)) return this.ProtectPassword;
			if(strField.equals(PwDefs.UrlField)) return this.ProtectUrl;
			if(strField.equals(PwDefs.NotesField)) return this.ProtectNotes;

			return false;
		}
	}
	// #pragma warning restore 1591 // Missing XML comments warning

	class ObjectTouchedEventArgs extends EventObject {
		private Object m_o;
		public Object getObject() { return m_o; }

		private boolean m_bModified;
		public boolean getModified() { return m_bModified; }

		private boolean m_bParentsTouched;
		public boolean getParentsTouched() { return m_bParentsTouched; }

		public ObjectTouchedEventArgs(Object o, boolean bModified,
			boolean bParentsTouched)
		{
            super(o);
			m_o = o;
			m_bModified = bModified;
			m_bParentsTouched = bParentsTouched;
		}
	}

	class IOAccessEventArgs extends EventObject
	{
		private IOConnectionInfo m_ioc;
		public IOConnectionInfo getIOConnectionInfo() { return m_ioc; }

		private IOConnectionInfo m_ioc2;
		public IOConnectionInfo getIOConnectionInfo2() { return m_ioc2; }

		private IOAccessType m_t;
		public IOAccessType getType() { return m_t; }

		public IOAccessEventArgs(IOConnectionInfo ioc, IOConnectionInfo ioc2,
			IOAccessType t)
		{
            super(ioc);
			m_ioc = ioc;
			m_ioc2 = ioc2;
			m_t = t;
		}
	}
