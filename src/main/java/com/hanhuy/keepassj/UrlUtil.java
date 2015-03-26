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

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/// <summary>
	/// A class containing various static path utility helper methods (like
	/// stripping extension from a file, etc.).
	/// </summary>
	public class UrlUtil
	{
		private static final char[] m_vDirSeps = new char[] {
			'\\', '/', UrlUtil.getLocalDirSepChar() };
		private static final char[] m_vPathTrimCharsWs = new char[] {
			'\"', ' ', '\t', '\r', '\n' };

		public static char getLocalDirSepChar()
		{
			 return File.separatorChar;
		}

		/// <summary>
		/// Get the directory (path) of a file name. The returned String may be
		/// terminated by a directory separator character. Example:
		/// passing <c>C:\\My Documents\\My File.kdb</c> in <paramref name="strFile" />
		/// and <c>true</c> to <paramref name="bAppendTerminatingChar"/>
		/// would produce this String: <c>C:\\My Documents\\</c>.
		/// </summary>
		/// <param name="strFile">Full path of a file.</param>
		/// <param name="bAppendTerminatingChar">Append a terminating directory separator
		/// character to the returned path.</param>
		/// <param name="bEnsureValidDirSpec">If <c>true</c>, the returned path
		/// is guaranteed to be a valid directory path (for example <c>X:\\</c> instead
		/// of <c>X:</c>, overriding <paramref name="bAppendTerminatingChar" />).
		/// This should only be set to <c>true</c>, if the returned path is directly
		/// passed to some directory API.</param>
		/// <returns>Directory of the file.</returns>
		public static String GetFileDirectory(String strFile, boolean bAppendTerminatingChar,
			boolean bEnsureValidDirSpec)
		{
			assert strFile != null;
			if(strFile == null) throw new IllegalArgumentException("strFile");

			int nLastSep = StrUtil.LastIndexOfAny(strFile, m_vDirSeps);
			if(nLastSep < 0) return ""; // No directory

			if(bEnsureValidDirSpec && (nLastSep == 2) && (strFile.charAt(1) == ':') &&
				(strFile.charAt(2) == '\\')) // Length >= 3 and Windows root directory
				bAppendTerminatingChar = true;

			if(!bAppendTerminatingChar) return strFile.substring(0, nLastSep);
			return EnsureTerminatingSeparator(strFile.substring(0, nLastSep),
				(strFile.charAt(nLastSep) == '/'));
		}

		/// <summary>
		/// Gets the file name of the specified file (full path). Example:
		/// if <paramref name="strPath" /> is <c>C:\\My Documents\\My File.kdb</c>
		/// the returned String is <c>My File.kdb</c>.
		/// </summary>
		/// <param name="strPath">Full path of a file.</param>
		/// <returns>File name of the specified file. The return value is
		/// an empty String (<c>""</c>) if the input parameter is <c>null</c>.</returns>
		public static String GetFileName(String strPath)
		{
			assert strPath != null; if(strPath == null) throw new IllegalArgumentException("strPath");

			int nLastSep = StrUtil.LastIndexOfAny(strPath, m_vDirSeps);

			if(nLastSep < 0) return strPath;
			if(nLastSep >= (strPath.length() - 1)) return "";

			return strPath.substring(nLastSep + 1);
		}

		/// <summary>
		/// Strip the extension of a file.
		/// </summary>
		/// <param name="strPath">Full path of a file with extension.</param>
		/// <returns>File name without extension.</returns>
		public static String StripExtension(String strPath)
		{
			assert strPath != null; if(strPath == null) throw new IllegalArgumentException("strPath");

			int nLastDirSep = StrUtil.LastIndexOfAny(strPath, m_vDirSeps);
			int nLastExtDot = strPath.lastIndexOf('.');

			if(nLastExtDot <= nLastDirSep) return strPath;

			return strPath.substring(0, nLastExtDot);
		}

		/// <summary>
		/// Get the extension of a file.
		/// </summary>
		/// <param name="strPath">Full path of a file with extension.</param>
		/// <returns>Extension without prepending dot.</returns>
		public static String GetExtension(String strPath)
		{
			assert strPath != null; if(strPath == null) throw new IllegalArgumentException("strPath");

			int nLastDirSep = StrUtil.LastIndexOfAny(strPath, m_vDirSeps);
			int nLastExtDot = strPath.lastIndexOf('.');

			if(nLastExtDot <= nLastDirSep) return "";
			if(nLastExtDot == (strPath.length() - 1)) return "";

			return strPath.substring(nLastExtDot + 1);
		}

		/// <summary>
		/// Ensure that a path is terminated with a directory separator character.
		/// </summary>
		/// <param name="strPath">Input path.</param>
		/// <param name="bUrl">If <c>true</c>, a slash (<c>/</c>) is appended to
		/// the String if it's not terminated already. If <c>false</c>, the
		/// default system directory separator character is used.</param>
		/// <returns>Path having a directory separator as last character.</returns>
		public static String EnsureTerminatingSeparator(String strPath, boolean bUrl)
		{
			assert strPath != null; if(strPath == null) throw new IllegalArgumentException("strPath");

			int nLength = strPath.length();
			if(nLength <= 0) return "";

			char chLast = strPath.charAt(nLength - 1);

			for(int i = 0; i < m_vDirSeps.length; ++i)
			{
				if(chLast == m_vDirSeps[i]) return strPath;
			}

			if(bUrl) return (strPath + '/');
			return (strPath + UrlUtil.getLocalDirSepChar());
		}

		/* /// <summary>
		/// File access mode enumeration. Used by the <c>FileAccessible</c>
		/// method.
		/// </summary>
		public enum FileAccessMode
		{
			/// <summary>
			/// Opening a file in read mode. The specified file must exist.
			/// </summary>
			Read = 0,

			/// <summary>
			/// Opening a file in create mode. If the file exists already, it
			/// will be overwritten. If it doesn't exist, it will be created.
			/// The return value is <c>true</c>, if data can be written to the
			/// file.
			/// </summary>
			Create
		} */

		/* /// <summary>
		/// Test if a specified path is accessible, either in read or write mode.
		/// </summary>
		/// <param name="strFilePath">Path to test.</param>
		/// <param name="fMode">Requested file access mode.</param>
		/// <returns>Returns <c>true</c> if the specified path is accessible in
		/// the requested mode, otherwise the return value is <c>false</c>.</returns>
		public static boolean FileAccessible(String strFilePath, FileAccessMode fMode)
		{
			assert strFilePath != null;
			if(strFilePath == null) throw new IllegalArgumentException("strFilePath");

			if(fMode == FileAccessMode.Read)
			{
				FileStream fs;

				try { fs = File.OpenRead(strFilePath); }
				catch(Exception) { return false; }
				if(fs == null) return false;

				fs.Close();
				return true;
			}
			else if(fMode == FileAccessMode.Create)
			{
				FileStream fs;

				try { fs = File.Create(strFilePath); }
				catch(Exception) { return false; }
				if(fs == null) return false;

				fs.Close();
				return true;
			}

			return false;
		} */

		public static String GetQuotedAppPath(String strPath)
		{
			if(strPath == null) { assert false; return ""; }

			// int nFirst = strPath.IndexOf('\"');
			// int nSecond = strPath.IndexOf('\"', nFirst + 1);
			// if((nFirst >= 0) && (nSecond >= 0))
			//	return strPath.Substring(nFirst + 1, nSecond - nFirst - 1);
			// return strPath;

			String str = strPath.trim();
			if(str.length() <= 1) return str;
			if(str.charAt(0) != '\"') return str;

			int iSecond = str.indexOf('\"', 1);
			if(iSecond <= 0) return str;

			return str.substring(1, iSecond - 1);
		}

		public static String FileUrlToPath(String strUrl)
		{
			assert strUrl != null;
			if(strUrl == null) throw new IllegalArgumentException("strUrl");

			String str = strUrl;
			if(str.toLowerCase().startsWith("file:///"))
				str = str.substring(8, str.length() - 8);

			str = str.replace('/', UrlUtil.getLocalDirSepChar());

			return str;
		}

		public static boolean UnhideFile(String strFile)
		{
			return false;
		}

		public static boolean HideFile(String strFile, boolean bHide)
		{
			return false;
		}

		public static String MakeRelativePath(String strBaseFile, String strTargetFile)
		{
			if(strBaseFile == null) throw new IllegalArgumentException("strBasePath");
			if(strTargetFile == null) throw new IllegalArgumentException("strTargetPath");
			if(strBaseFile.length() == 0) return strTargetFile;
			if(strTargetFile.length() == 0) return "";

			// Test whether on different Windows drives
			if((strBaseFile.length() >= 3) && (strTargetFile.length() >= 3))
			{
				if((strBaseFile.charAt(1) == ':') && (strTargetFile.charAt(1) == ':') &&
					(strBaseFile.charAt(2) == '\\') && (strTargetFile.charAt(2) == '\\') &&
					(strBaseFile.charAt(0) != strTargetFile.charAt(0)))
					return strTargetFile;
			}

			if(!System.getProperty("os.name").contains("Windows"))
			{
				boolean bBaseUnc = IsUncPath(strBaseFile);
				boolean bTargetUnc = IsUncPath(strTargetFile);
				if((!bBaseUnc && bTargetUnc) || (bBaseUnc && !bTargetUnc))
					return strTargetFile;

				String strBase = GetShortestAbsolutePath(strBaseFile);
				String strTarget = GetShortestAbsolutePath(strTargetFile);
				String[] vBase = strBase.split("[\\\\/]");
				String[] vTarget = strTarget.split("[\\\\/]");

				int i = 0;
				while((i < (vBase.length - 1)) && (i < (vTarget.length - 1)) &&
					(vBase[i].equals(vTarget[i]))) { ++i; }

				StringBuilder sbRel = new StringBuilder();
				for(int j = i; j < (vBase.length - 1); ++j)
				{
					if(sbRel.length() > 0) sbRel.append(UrlUtil.getLocalDirSepChar());
					sbRel.append("..");
				}
				for(int k = i; k < vTarget.length; ++k)
				{
					if(sbRel.length() > 0) sbRel.append(UrlUtil.getLocalDirSepChar());
					sbRel.append(vTarget[k]);
				}

				return sbRel.toString();
			}
            return strTargetFile;
		}

		public static String MakeAbsolutePath(String strBaseFile, String strTargetFile)
		{
			if(strBaseFile == null) throw new IllegalArgumentException("strBasePath");
			if(strTargetFile == null) throw new IllegalArgumentException("strTargetPath");
			if(strBaseFile.length() == 0) return strTargetFile;
			if(strTargetFile.length() == 0) return "";

			if(IsAbsolutePath(strTargetFile)) return strTargetFile;

			String strBaseDir = GetFileDirectory(strBaseFile, true, false);
			return GetShortestAbsolutePath(strBaseDir + strTargetFile);
		}

		public static boolean IsAbsolutePath(String strPath)
		{
			if(strPath == null) throw new IllegalArgumentException("strPath");
			if(strPath.length() == 0) return false;

			if(IsUncPath(strPath)) return true;

            return strPath.startsWith("/") || strPath.startsWith("\\") || (strPath.charAt(1) == ':');
		}

		public static String GetShortestAbsolutePath(String strPath)
		{
			if(strPath == null) throw new IllegalArgumentException("strPath");
			if(strPath.length() == 0) return "";

			// Path.GetFullPath is incompatible with UNC paths traversing over
			// different server shares (which are created by PathRelativePathTo);
			// we need to build the absolute path on our own...
			if(IsUncPath(strPath))
			{
				char chSep = strPath.charAt(0);

				List<String> l = new ArrayList<String>();
				String[] v = strPath.split("[\\\\/]");
				assert (v.length >= 3) && (v[0].length() == 0) &&
					(v[1].length() == 0);

				for(String strPart : v)
				{
					if(strPart.equals(".")) continue;
					else if(strPart.equals(".."))
					{
						if(l.size() > 0) l.remove(l.size() - 1);
						else { assert false; }
					}
					else l.add(strPart); // Do not ignore zero length parts
				}

				StringBuilder sb = new StringBuilder();
				for(int i = 0; i < l.size(); ++i)
				{
					// Don't test length of sb, might be 0 due to initial UNC seps
					if(i > 0) sb.append(chSep);

					sb.append(l.get(i));
				}

				return sb.toString();
			}

			String str;
			try
			{
				str = new File(strPath).getCanonicalPath();
			}
			catch(Exception e) { assert false; return strPath; }

			assert str.indexOf("\\..\\") < 0;
			for(char ch : m_vDirSeps)
			{
				String strSep = String.valueOf(ch);
				str = str.replace(strSep + "." + strSep, strSep);
			}

			return str;
		}

		public static int GetUrlLength(String strText, int nOffset)
		{
			if(strText == null) throw new IllegalArgumentException("strText");
			if(nOffset > strText.length()) throw new IllegalArgumentException(); // Not >= (0 len)

			int iPosition = nOffset, nLength = 0, nStrLen = strText.length();

			while(iPosition < nStrLen)
			{
				char ch = strText.charAt(iPosition);
				++iPosition;

				if((ch == ' ') || (ch == '\t') || (ch == '\r') || (ch == '\n'))
					break;

				++nLength;
			}

			return nLength;
		}

		public static String RemoveScheme(String strUrl)
		{
			if(Strings.isNullOrEmpty(strUrl)) return "";

			int nNetScheme = strUrl.indexOf("://");
			int nShScheme = strUrl.indexOf(":/");
			int nSmpScheme = strUrl.indexOf(":");

			if((nNetScheme < 0) && (nShScheme < 0) && (nSmpScheme < 0))
				return strUrl; // No scheme

			int nMin = Math.min(Math.min((nNetScheme >= 0) ? nNetScheme : Integer.MAX_VALUE,
                            (nShScheme >= 0) ? nShScheme : Integer.MAX_VALUE),
                    (nSmpScheme >= 0) ? nSmpScheme : Integer.MAX_VALUE);

			if(nMin == nNetScheme) return strUrl.substring(nMin + 3);
			if(nMin == nShScheme) return strUrl.substring(nMin + 2);
			return strUrl.substring(nMin + 1);
		}

		public static String ConvertSeparators(String strPath)
		{
			return ConvertSeparators(strPath, UrlUtil.getLocalDirSepChar());
		}

		public static String ConvertSeparators(String strPath, char chSeparator)
		{
			if(Strings.isNullOrEmpty(strPath)) return "";

			strPath = strPath.replace('/', chSeparator);
			strPath = strPath.replace('\\', chSeparator);

			return strPath;
		}

		public static boolean IsUncPath(String strPath)
		{
			if(strPath == null) throw new IllegalArgumentException("strPath");

			return (strPath.startsWith("\\\\") || strPath.startsWith("//"));
		}

		public static String FilterFileName(String strName)
		{
			if(strName == null) { assert false; return ""; }

			String str = strName;

			str = str.replace('/', '-');
			str = str.replace('\\', '-');
			str = str.replace(":", "");
			str = str.replace("*", "");
			str = str.replace("?", "");
			str = str.replace("\"", "");
			str = str.replace("'", "");
			str = str.replace('<', '(');
			str = str.replace('>', ')');
			str = str.replace('|', '-');

			return str;
		}

		/// <summary>
		/// Get the host component of an URL.
		/// This method is faster and more fault-tolerant than creating
		/// an <code>Uri</code> object and querying its <code>Host</code>
		/// property.
		/// </summary>
		/// <example>
		/// For the input <code>s://u:p@d.tld:p/p?q#f</code> the return
		/// value is <code>d.tld</code>.
		/// </example>
		public static String GetHost(String strUrl)
		{
			if(strUrl == null) { assert false; return ""; }

			StringBuilder sb = new StringBuilder();
			boolean bInExtHost = false;
			for(int i = 0; i < strUrl.length(); ++i)
			{
				char ch = strUrl.charAt(i);
				if(bInExtHost)
				{
					if(ch == '/')
					{
						if(sb.length() == 0) { } // Ignore leading '/'s
						else break;
					}
					else sb.append(ch);
				}
				else // !bInExtHost
				{
					if(ch == ':') bInExtHost = true;
				}
			}

			String str = sb.toString();
			if(str.length() == 0) str = strUrl;

			// Remove the login part
			int nLoginLen = str.indexOf('@');
			if(nLoginLen >= 0) str = str.substring(nLoginLen + 1);

			// Remove the port
			int iPort = str.lastIndexOf(':');
			if(iPort >= 0) str = str.substring(0, iPort);

			return str;
		}

		public static boolean AssemblyEquals(String strExt, String strShort)
		{
			if((strExt == null) || (strShort == null)) { assert false; return false; }

			if(strExt.equalsIgnoreCase(strShort) ||
				strExt.toLowerCase().startsWith(strShort.toLowerCase() + ","))
				return true;

			if(!strShort.toLowerCase().endsWith(".dll"))
			{
				if(strExt.equalsIgnoreCase(strShort + ".dll") ||
					strExt.toLowerCase().startsWith(strShort.toLowerCase() + ".dll,"))
					return true;
			}

			if(!strShort.toLowerCase().endsWith(".exe"))
			{
				if(strExt.equalsIgnoreCase(strShort + ".exe") ||
					strExt.toLowerCase().startsWith(strShort.toLowerCase() + ".exe,"))
					return true;
			}

			return false;
		}

		public static String GetTempPath()
		{
			String strDir;
			strDir = System.getProperty("java.io.tmpdir");
            File f = new File(strDir);

			try
			{
				if(f.isDirectory())
					f.mkdirs();
			}
			catch(Exception e) { assert false; }

			return strDir;
		}

        /*
		// Structurally mostly equivalent to UrlUtil.GetFileInfos
		public static List<String> GetFilePaths(String strDir, String strPattern,
			SearchOption opt)
		{
			List<String> l = new List<String>();
			if(strDir == null) { assert false; return l; }
			if(strPattern == null) { assert false; return l; }

			String[] v = Directory.GetFiles(strDir, strPattern, opt);
			if(v == null) { assert false; return l; }

			// Only accept files with the correct extension; GetFiles may
			// return additional files, see GetFiles documentation
			String strExt = GetExtension(strPattern);
			if(!String.IsNullOrEmpty(strExt) && (strExt.IndexOf('*') < 0) &&
				(strExt.IndexOf('?') < 0))
			{
				strExt = "." + strExt;

				foreach(String strPathRaw in v)
				{
					if(strPathRaw == null) { assert false; continue; }
					String strPath = strPathRaw.Trim(m_vPathTrimCharsWs);
					if(strPath.Length == 0) { assert false; continue; }
					assert strPath == strPathRaw;

					if(!strPath.EndsWith(strExt, StrUtil.CaseIgnoreCmp))
						continue;

					l.Add(strPathRaw);
				}
			}
			else l.AddRange(v);

			return l;
		}
		*/

		// Structurally mostly equivalent to UrlUtil.GetFilePaths
        /*
		public static List<File> GetFileInfos(File di, String strPattern,
			SearchOption opt)
		{
			List<File> l = new ArrayList<File>();
			if(di == null) { assert false; return l; }
			if(strPattern == null) { assert false; return l; }

			File[] v = di.GetFiles(strPattern, opt);
			if(v == null) { assert false; return l; }

			// Only accept files with the correct extension; GetFiles may
			// return additional files, see GetFiles documentation
			String strExt = GetExtension(strPattern);
			if(!String.IsNullOrEmpty(strExt) && (strExt.IndexOf('*') < 0) &&
				(strExt.IndexOf('?') < 0))
			{
				strExt = "." + strExt;

				foreach(FileInfo fi in v)
				{
					if(fi == null) { assert false; continue; }
					String strPathRaw = fi.FullName;
					if(strPathRaw == null) { assert false; continue; }
					String strPath = strPathRaw.Trim(m_vPathTrimCharsWs);
					if(strPath.Length == 0) { assert false; continue; }
					assert strPath == strPathRaw;

					if(!strPath.EndsWith(strExt, StrUtil.CaseIgnoreCmp))
						continue;

					l.Add(fi);
				}
			}
			else l.AddRange(v);

			return l;
		}
		*/
	}
