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

import com.google.common.base.Objects;
import com.google.common.base.Predicate;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.hanhuy.keepassj.*;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/// <summary>
	/// String placeholders and field reference replacement engine.
	/// </summary>
	public class SprEngine
	{
		private final static int MaxRecursionDepth = 12;

		private static String m_strAppExePath = "";
		// private static readonly char[] m_vPlhEscapes = new char[] { '{', '}', '%' };

		// Important notes for plugin developers subscribing to the following events:
		// * If possible, prefer subscribing to FilterCompile instead of
		//   FilterCompilePre.
		// * If your plugin provides an active transformation (e.g. replacing a
		//   placeholder that changes some state or requires UI interaction), you
		//   must only perform the transformation if the ExtActive bit is set in
		//   args.Context.Flags of the event arguments object args provided to the
		//   event handler.
		// * Non-active transformations should only be performed if the ExtNonActive
		//   bit is set in args.Context.Flags.
		// * If your plugin provides a placeholder (like e.g. {EXAMPLE}), you
		//   should add this placeholder to the FilterPlaceholderHints list
		//   (e.g. add the String "{EXAMPLE}"). Please remove your strings from
		//   the list when your plugin is terminated.
		public static EventHandler<SprEventArgs> FilterCompilePre;
		public static EventHandler<SprEventArgs> FilterCompile;

		private static List<String> m_lFilterPlh = new ArrayList<String>();
		// See the events above
		public static List<String> getFilterPlaceholderHints()
		{
			return m_lFilterPlh;
		}

		@Deprecated
		public static String Compile(String strText, boolean bIsAutoTypeSequence,
			PwEntry pwEntry, PwDatabase pwDatabase, boolean bEscapeForAutoType,
			boolean bEscapeQuotesForCommandLine)
		{
			SprContext ctx = new SprContext(pwEntry, pwDatabase, SprCompileFlags.All.flags,
				bEscapeForAutoType, bEscapeQuotesForCommandLine);
			return Compile(strText, ctx);
		}

		public static String Compile(String strText, SprContext ctx)
		{
			if(strText == null) { assert false; return ""; }
			if(strText.length() == 0) return "";

			if(ctx == null) ctx = new SprContext();
			ctx.getRefsCache().clear();

			String str = SprEngine.CompileInternal(strText, ctx, 0);

			// if(bEscapeForAutoType && !bIsAutoTypeSequence)
			//	str = SprEncoding.MakeAutoTypeSequence(str);

			return str;
		}

		private static String CompileInternal(String strText, SprContext ctx,
			int uRecursionLevel)
		{
			if(strText == null) { assert false; return ""; }
			if(ctx == null) { assert false; ctx = new SprContext(); }

			if(uRecursionLevel >= SprEngine.MaxRecursionDepth)
			{
				assert false; // Most likely a recursive reference
				return ""; // Do not return strText (endless loop)
			}

			String str = strText;

			boolean bExt = ctx.getFlags().contains(SprCompileFlags.or(SprCompileFlags.ExtActive,
				SprCompileFlags.ExtNonActive));
			if(bExt && (SprEngine.FilterCompilePre != null))
			{
				SprEventArgs args = new SprEventArgs(str, ctx.clone());
				SprEngine.FilterCompilePre.delegate(null, args);
				str = args.getText();
			}

			if(ctx.getFlags().contains(SprCompileFlags.Comments))
				str = RemoveComments(str);

			if(ctx.getFlags().contains(SprCompileFlags.TextTransforms))
				str = PerformTextTransforms(str, ctx, uRecursionLevel);

            /*
			if((ctx.getFlags() & SprCompileFlags.AppPaths) != SprCompileFlags.None)
				str = AppLocator.FillPlaceholders(str, ctx);
				*/

			if(ctx.getEntry() != null)
			{
				if(ctx.getFlags().contains(SprCompileFlags.PickChars))
					str = ReplacePickPw(str, ctx, uRecursionLevel);

				if(ctx.getFlags().contains(SprCompileFlags.EntryStrings))
					str = FillEntryStrings(str, ctx, uRecursionLevel);

				if(ctx.getFlags().contains(SprCompileFlags.EntryStringsSpecial))
				{
					// ctx.UrlRemoveSchemeOnce = true;
					// str = SprEngine.FillIfExists(str, "{URL:RMVSCM}",
					//	ctx.Entry.Strings.GetSafe(PwDefs.UrlField), ctx, uRecursionLevel);
					// assert !ctx.UrlRemoveSchemeOnce;

					str = FillEntryStringsSpecial(str, ctx, uRecursionLevel);
				}

				if((ctx.getFlags().contains(SprCompileFlags.PasswordEnc)) &&
					(str.toUpperCase().indexOf("{PASSWORD_ENC}") >= 0))
				{
					String strPwCmp = SprEngine.FillIfExists("{PASSWORD}",
						"{PASSWORD}", ctx.getEntry().getStrings().GetSafe(PwDefs.PasswordField),
						ctx.WithoutContentTransformations(), uRecursionLevel);

					str = SprEngine.FillPlaceholder(str, "{PASSWORD_ENC}",
						StrUtil.EncryptString(strPwCmp), ctx);
				}

				if((ctx.getFlags().contains(SprCompileFlags.Group)) &&
					(ctx.getEntry().getParentGroup() != null))
				{
					str = SprEngine.FillIfExists(str, "{GROUP}", new ProtectedString(
						false, ctx.getEntry().getParentGroup().getName()), ctx, uRecursionLevel);

					str = SprEngine.FillIfExists(str, "{GROUPPATH}", new ProtectedString(
						false, ctx.getEntry().getParentGroup().GetFullPath()), ctx, uRecursionLevel);
				}
			}

            /*
			if((ctx.Flags & SprCompileFlags.Paths) != SprCompileFlags.None)
				str = SprEngine.FillIfExists(str, "{APPDIR}", new ProtectedString(
					false, UrlUtil.GetFileDirectory(m_strAppExePath, false, false)),
					ctx, uRecursionLevel);
					*/

			if(ctx.getDatabase() != null)
			{
				if((ctx.getFlags().contains(SprCompileFlags.Paths)))
				{
					// For backward compatibility only
					str = SprEngine.FillIfExists(str, "{DOCDIR}", new ProtectedString(
						false, UrlUtil.GetFileDirectory(ctx.getDatabase().getIOConnectionInfo().getPath(),
						false, false)), ctx, uRecursionLevel);

					str = SprEngine.FillIfExists(str, "{DB_PATH}", new ProtectedString(
						false, ctx.getDatabase().getIOConnectionInfo().getPath()), ctx, uRecursionLevel);
					str = SprEngine.FillIfExists(str, "{DB_DIR}", new ProtectedString(
						false, UrlUtil.GetFileDirectory(ctx.getDatabase().getIOConnectionInfo().getPath(),
						false, false)), ctx, uRecursionLevel);
					str = SprEngine.FillIfExists(str, "{DB_NAME}", new ProtectedString(
						false, UrlUtil.GetFileName(ctx.getDatabase().getIOConnectionInfo().getPath())),
						ctx, uRecursionLevel);
					str = SprEngine.FillIfExists(str, "{DB_BASENAME}", new ProtectedString(
						false, UrlUtil.StripExtension(UrlUtil.GetFileName(
						ctx.getDatabase().getIOConnectionInfo().getPath()))), ctx, uRecursionLevel);
					str = SprEngine.FillIfExists(str, "{DB_EXT}", new ProtectedString(
						false, UrlUtil.GetExtension(ctx.getDatabase().getIOConnectionInfo().getPath())),
						ctx, uRecursionLevel);
				}
			}

            /*
			if((ctx.getFlags() & SprCompileFlags.Paths) != SprCompileFlags.None)
			{
				str = SprEngine.FillIfExists(str, "{ENV_DIRSEP}", new ProtectedString(
					false, File.separator), ctx, uRecursionLevel);

				String strPF86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
				if(String.IsNullOrEmpty(strPF86))
					strPF86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
				if(strPF86 != null)
					str = SprEngine.FillIfExists(str, "{ENV_PROGRAMFILES_X86}",
						new ProtectedString(false, strPF86), ctx, uRecursionLevel);
				else { assert false; }
			}
			*/

			if(ctx.getFlags().contains(SprCompileFlags.AutoType))
			{
				// Use Bksp instead of Del (in order to avoid Ctrl+Alt+Del);
				// https://sourceforge.net/p/keepass/discussion/329220/thread/4f1aa6b8/
				str = StrUtil.ReplaceCaseInsensitive(str, "{CLEARFIELD}",
					"{HOME}+({END}){BKSP}{DELAY 50}");
			}

			if(ctx.getFlags().contains(SprCompileFlags.DateTime))
			{
				Date dtNow = new Date(); // Local time
                SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss");
                String d2 = "%02d";
                String d4 = "%04d";
                Calendar c = Calendar.getInstance();
                c.setTime(dtNow);
				str = SprEngine.FillIfExists(str, "{DT_YEAR}", new ProtectedString(
					false, String.format(d4, c.get(Calendar.YEAR))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_MONTH}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.MONTH))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_DAY}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.DAY_OF_MONTH))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_HOUR}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.HOUR_OF_DAY))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_MINUTE}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.MINUTE))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_SECOND}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.SECOND))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_SIMPLE}", new ProtectedString(
					false, fmt.format(dtNow)), ctx, uRecursionLevel);

                SimpleDateFormat utcfmt = new SimpleDateFormat("yyyyMMddHHmmss");
                utcfmt.setTimeZone(TimeUtil.UTC);
                c.setTimeZone(TimeUtil.UTC);
				str = SprEngine.FillIfExists(str, "{DT_UTC_YEAR}", new ProtectedString(
					false, String.format(d4, c.get(Calendar.YEAR))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_UTC_MONTH}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.MONTH))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_UTC_DAY}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.DAY_OF_MONTH))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_UTC_HOUR}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.HOUR_OF_DAY))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_UTC_MINUTE}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.MINUTE))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_UTC_SECOND}", new ProtectedString(
					false, String.format(d2, c.get(Calendar.SECOND))), ctx, uRecursionLevel);
				str = SprEngine.FillIfExists(str, "{DT_UTC_SIMPLE}", new ProtectedString(
					false, utcfmt.format(dtNow)), ctx, uRecursionLevel);
			}

			if(ctx.getFlags().contains(SprCompileFlags.References))
				str = SprEngine.FillRefPlaceholders(str, ctx, uRecursionLevel);


			if((ctx.getFlags().contains(SprCompileFlags.EnvVars)) &&
				(str.indexOf('%') >= 0))
			{
				// Replace environment variables
				for(Map.Entry<String,String> de : System.getenv().entrySet())
				{
					String strKey = de.getKey();
					String strValue = de.getValue();

					if((strKey != null) && (strValue != null))
						str = SprEngine.FillIfExists(str, "%" + strKey + "%",
							new ProtectedString(false, strValue), ctx, uRecursionLevel);
					else { assert false; }
				}
			}

			if(ctx.getFlags().contains(SprCompileFlags.Env))
				str = FillUriSpecial(str, ctx, "{BASE", (Strings.nullToEmpty(ctx.getBase())),
					ctx.getBaseIsEncoded(), uRecursionLevel);

			str = EntryUtil.FillPlaceholders(str, ctx, uRecursionLevel);

			if(ctx.getFlags().contains(SprCompileFlags.PickChars))
				str = ReplacePickChars(str, ctx, uRecursionLevel);

			if(bExt && (SprEngine.FilterCompile != null))
			{
				SprEventArgs args = new SprEventArgs(str, ctx.clone());
				SprEngine.FilterCompile.delegate(null, args);
				str = args.getText();
			}

			if(ctx.getEncodeAsAutoTypeSequence())
			{
				str = StrUtil.NormalizeNewLines(str, false);
				str = str.replace("\n", "{ENTER}");
			}

			return str;
		}

		private static String FillIfExists(String strData, String strPlaceholder,
			ProtectedString psParsable, SprContext ctx, int uRecursionLevel)
		{
			// // The UrlRemoveSchemeOnce property of ctx must be cleared
			// // before this method returns and before any recursive call
			// boolean bRemoveScheme = false;
			// if(ctx != null)
			// {
			//	bRemoveScheme = ctx.UrlRemoveSchemeOnce;
			//	ctx.UrlRemoveSchemeOnce = false;
			// }

			if(strData == null) { assert false; return ""; }
			if(strPlaceholder == null) { assert false; return strData; }
			if(strPlaceholder.length() == 0) { assert false; return strData; }
			if(psParsable == null) { assert false; return strData; }

			if(strData.toLowerCase().indexOf(strPlaceholder.toLowerCase()) >= 0)
			{
				String strReplacement = SprEngine.CompileInternal(
					psParsable.ReadString(), ctx.WithoutContentTransformations(),
					uRecursionLevel + 1);

				// if(bRemoveScheme)
				//	strReplacement = UrlUtil.RemoveScheme(strReplacement);

				return SprEngine.FillPlaceholder(strData, strPlaceholder,
					strReplacement, ctx);
			}

			return strData;
		}

		private static String FillPlaceholder(String strData, String strPlaceholder,
			String strReplaceWith, SprContext ctx)
		{
			if(strData == null) { assert false; return ""; }
			if(strPlaceholder == null) { assert false; return strData; }
			if(strPlaceholder.length() == 0) { assert false; return strData; }
			if(strReplaceWith == null) { assert false; return strData; }

			return StrUtil.ReplaceCaseInsensitive(strData, strPlaceholder,
				SprEngine.TransformContent(strReplaceWith, ctx));
		}

		public static String TransformContent(String strContent, SprContext ctx)
		{
			if(strContent == null) { assert false; return ""; }

			String str = strContent;

			if(ctx != null)
			{
				if(ctx.getEncodeQuotesForCommandLine())
					str = SprEncoding.MakeCommandQuotes(str);

				if(ctx.getEncodeAsAutoTypeSequence())
					str = SprEncoding.MakeAutoTypeSequence(str);
			}

			return str;
		}

		private static String FillEntryStrings(String str, SprContext ctx,
			int uRecursionLevel)
		{
			List<String> vKeys = ctx.getEntry().getStrings().GetKeys();

			// Ensure that all standard field names are in the list
			// (this is required in order to replace the standard placeholders
			// even if the corresponding standard field isn't present in
			// the entry)
			List<String> vStdNames = PwDefs.GetStandardFields();
			for(String strStdField : vStdNames)
			{
				if(!vKeys.contains(strStdField)) vKeys.add(strStdField);
			}

			// Do not directly enumerate the strings in ctx.Entry.Strings,
			// because strings might change during the Spr compilation
			for(String strField : vKeys)
			{
				String strKey = (PwDefs.IsStandardField(strField) ?
					("{" + strField + "}") :
					("{" + PwDefs.AutoTypeStringPrefix + strField + "}"));

				if(!ctx.getForcePlainTextPasswords() && strKey.equalsIgnoreCase("{" +
					PwDefs.PasswordField + "}"))
				{
					str = SprEngine.FillIfExists(str, strKey, new ProtectedString(
						false, PwDefs.HiddenPassword), ctx, uRecursionLevel);
					continue;
				}

				// Use GetSafe because the field doesn't necessarily exist
				// (might be a standard field that has been added above)
				str = SprEngine.FillIfExists(str, strKey, ctx.getEntry().getStrings().GetSafe(
                        strField), ctx, uRecursionLevel);
			}

			return str;
		}

		private static String FillEntryStringsSpecial(String str, SprContext ctx,
			int uRecursionLevel)
		{
			return FillUriSpecial(str, ctx, "{URL", ctx.getEntry().getStrings().ReadSafe(
                    PwDefs.UrlField), false, uRecursionLevel);
		}

		private static String FillUriSpecial(String strText, SprContext ctx,
			String strPlhInit, String strData, boolean bDataIsEncoded,
			int uRecursionLevel)
		{
			assert strPlhInit.startsWith("{") && !strPlhInit.endsWith("}");
			assert strData != null;

			String[] vPlhs = new String[] {
				strPlhInit + "}",
				strPlhInit + ":RMVSCM}",
				strPlhInit + ":SCM}",
				strPlhInit + ":HOST}",
				strPlhInit + ":PORT}",
				strPlhInit + ":PATH}",
				strPlhInit + ":QUERY}",
				strPlhInit + ":USERINFO}",
				strPlhInit + ":USERNAME}",
				strPlhInit + ":PASSWORD}"
			};

			String str = strText;
			String strDataCmp = null;
			URI uri = null;
			for(int i = 0; i < vPlhs.length; ++i)
			{
				String strPlh = vPlhs[i];
				if(str.toLowerCase().indexOf(strPlh.toLowerCase()) < 0) continue;

				if(strDataCmp == null)
				{
					SprContext ctxData = (bDataIsEncoded ?
						ctx.WithoutContentTransformations() : ctx);
					strDataCmp = SprEngine.CompileInternal(strData, ctxData,
						uRecursionLevel + 1);
				}

				String strRep = null;
				if(i == 0) strRep = strDataCmp;
				else if(i == 1) strRep = UrlUtil.RemoveScheme(strDataCmp);
				else
				{
					try
					{
						if(uri == null) uri = new URI(strDataCmp);

						int t;
						switch(i)
						{
							case 2: strRep = uri.getScheme(); break;
							case 3: strRep = uri.getHost(); break;
							case 4:
								strRep = String.valueOf(uri.getPort());
								break;
							case 5: strRep = uri.getPath(); break;
							case 6: strRep = uri.getQuery(); break;
							case 7: strRep = uri.getUserInfo(); break;
							case 8:
								strRep = uri.getUserInfo();
								t = strRep.indexOf(':');
								if(t >= 0) strRep = strRep.substring(0, t);
								break;
							case 9:
								strRep = uri.getUserInfo();
								t = strRep.indexOf(':');
								if(t < 0) strRep = "";
								else strRep = strRep.substring(t + 1);
								break;
							default: assert false; break;
						}
					}
					catch(Exception e) { } // Invalid URI
				}
				if(strRep == null) strRep = ""; // No assert

				str = StrUtil.ReplaceCaseInsensitive(str, strPlh, strRep);
			}

			return str;
		}

		private final static String StrRemStart = "{C:";
		private final static String StrRemEnd = "}";
		private static String RemoveComments(String strSeq)
		{
			String str = strSeq;

			while(true)
			{
				int iStart = str.toLowerCase().indexOf(StrRemStart.toLowerCase());
				if(iStart < 0) break;
				int iEnd = str.toLowerCase().indexOf(StrRemEnd.toLowerCase(), iStart + 1);
				if(iEnd <= iStart) break;

				str = (str.substring(0, iStart) + str.substring(iEnd + StrRemEnd.length()));
			}

			return str;
		}

		final static String StrRefStart = "{REF:";
		final static String StrRefEnd = "}";
		private static String FillRefPlaceholders(String strSeq, SprContext ctx,
			int uRecursionLevel)
		{
			if(ctx.getDatabase() == null) return strSeq;

			String str = strSeq;

			int nOffset = 0;
			for(int iLoop = 0; iLoop < 20; ++iLoop)
			{
				str = SprEngine.FillRefsUsingCache(str, ctx);

				int nStart = str.toLowerCase().indexOf(StrRefStart.toLowerCase(), nOffset);
				if(nStart < 0) break;
				int nEnd = str.toLowerCase().indexOf(StrRefEnd.toLowerCase(), nStart + 1);
				if(nEnd <= nStart) break;

				String strFullRef = str.substring(nStart, nEnd - nStart + 1);
				char[] chScan = new char[1], chWanted = new char[1];
				PwEntry peFound = FindRefTarget(strFullRef, ctx, chScan, chWanted);

				if(peFound != null)
				{
					String strInsData;
					if(chWanted[0] == 'T')
						strInsData = peFound.getStrings().ReadSafe(PwDefs.TitleField);
					else if(chWanted[0] == 'U')
						strInsData = peFound.getStrings().ReadSafe(PwDefs.UserNameField);
					else if(chWanted[0] == 'A')
						strInsData = peFound.getStrings().ReadSafe(PwDefs.UrlField);
					else if(chWanted[0] == 'P')
						strInsData = peFound.getStrings().ReadSafe(PwDefs.PasswordField);
					else if(chWanted[0] == 'N')
						strInsData = peFound.getStrings().ReadSafe(PwDefs.NotesField);
					else if(chWanted[0] == 'I')
						strInsData = peFound.getUuid().ToHexString();
					else { nOffset = nStart + 1; continue; }

					if((chWanted[0] == 'P') && !ctx.getForcePlainTextPasswords())
						strInsData = PwDefs.HiddenPassword;

					SprContext sprSub = ctx.WithoutContentTransformations();
					sprSub.setEntry(peFound);

					String strInnerContent = SprEngine.CompileInternal(strInsData,
						sprSub, uRecursionLevel + 1);
					strInnerContent = SprEngine.TransformContent(strInnerContent, ctx);

					// str = str.Substring(0, nStart) + strInnerContent + str.Substring(nEnd + 1);
					SprEngine.AddRefToCache(strFullRef, strInnerContent, ctx);
					str = SprEngine.FillRefsUsingCache(str, ctx);
				}
				else { nOffset = nStart + 1; continue; }
			}

			return str;
		}

		public static PwEntry FindRefTarget(String strFullRef, SprContext ctx,
			char[] chScan, char[] chWanted)
		{
			chScan[0] = Character.MIN_VALUE;
			chWanted[0] = Character.MIN_VALUE;

			if(strFullRef == null) { assert false; return null; }
			if(!strFullRef.toLowerCase().startsWith(StrRefStart.toLowerCase()) ||
				!strFullRef.toLowerCase().endsWith(StrRefEnd.toLowerCase()))
				return null;
			if((ctx == null) || (ctx.getDatabase() == null)) { assert false; return null; }

			String strRef = strFullRef.substring(StrRefStart.length(),
                    strFullRef.length() - StrRefStart.length() - StrRefEnd.length());
			if(strRef.length() <= 4) return null;
			if(strRef.charAt(1) != '@') return null;
			if(strRef.charAt(3) != ':') return null;

			chScan[0] = Character.toUpperCase(strRef.charAt(2));
			chWanted[0] = Character.toUpperCase(strRef.charAt(0));

			SearchParameters sp = SearchParameters.getNone();
			sp.setSearchString(strRef.substring(4));
			sp.setRespectEntrySearchingDisabled(false);

			if(chScan[0] == 'T') sp.setSearchInTitles(true);
			else if(chScan[0] == 'U') sp.setSearchInUserNames(true);
			else if(chScan[0] == 'A') sp.setSearchInUrls(true);
			else if(chScan[0] == 'P') sp.setSearchInPasswords(true);
			else if(chScan[0] == 'N') sp.setSearchInNotes(true);
			else if(chScan[0] == 'I') sp.setSearchInUuids(true);
			else if(chScan[0] == 'O') sp.setSearchInOther(true);
			else return null;

			PwObjectList<PwEntry> lFound = new PwObjectList<PwEntry>();
			ctx.getDatabase().getRootGroup().SearchEntries(sp, lFound);

			return ((lFound.getUCount() > 0) ? lFound.GetAt(0) : null);
		}

		private static String FillRefsUsingCache(String strText, SprContext ctx)
		{
			String str = strText;

			for(Map.Entry<String, String> kvp : ctx.getRefsCache().entrySet())
			{
				// str = str.Replace(kvp.Key, kvp.Value);
				str = StrUtil.ReplaceCaseInsensitive(str, kvp.getKey(), kvp.getValue());
			}

			return str;
		}

		private static void AddRefToCache(String strRef, String strValue,
			SprContext ctx)
		{
			if(strRef == null) { assert false; return; }
			if(strValue == null) { assert false; return; }
			if(ctx == null) { assert false; return; }

			// Only add if not exists, do not overwrite
			if(!ctx.getRefsCache().containsKey(strRef))
				ctx.getRefsCache().put(strRef, strValue);
		}

		// static boolean MightChange(String strText)
		// {
		//	if(String.IsNullOrEmpty(strText)) return false;
		//	return (strText.IndexOfAny(m_vPlhEscapes) >= 0);
		// }

		/// <summary>
		/// Fast probabilistic test whether a String might be
		/// changed when compiling with <c>SprCompileFlags.Deref</c>.
		/// </summary>
		static boolean MightDeref(String strText)
		{
			if(strText == null) return false;
			return (strText.indexOf('{') >= 0);
		}

        /* TODO what do I do here?
		static String DerefFn(String str, PwEntry pe)
		{
			if(!MightDeref(str)) return str;

			SprContext ctx = new SprContext(pe,
				Program.MainForm.DocumentManager.SafeFindContainerOf(pe),
				SprCompileFlags.Deref);
			// ctx.ForcePlainTextPasswords = false;

			return Compile(str, ctx);
		}
		*/

		/// <summary>
		/// Parse and remove a placeholder of the form
		/// <c>{PLH:/Param1/Param2/.../}</c>.
		/// </summary>
		static boolean ParseAndRemovePlhWithParams(String[] str,
			SprContext ctx, int uRecursionLevel, String strPlhStart,
			int[] iStart, List<String> lParams, boolean bSprCmpParams)
		{
			assert strPlhStart.startsWith("{") && !strPlhStart.endsWith("}");

			iStart[0] = str[0].toLowerCase().indexOf(strPlhStart.toLowerCase());
			if(iStart[0] < 0) { lParams.clear(); return false; }

			lParams.clear();

			try
			{
				int p = iStart[0] + strPlhStart.length();
				if(p >= str[0].length()) throw new ParseException(str[0], p);

				char chSep = str[0].charAt(p);

				while(true)
				{
					if((p + 1) >= str[0].length()) throw new ParseException(str[0], p + 1);

					if(str[0].charAt(p + 1) == '}') break;

					int q = str[0].indexOf(chSep, p + 1);
					if(q < 0) throw new ParseException(str[0], q);

					lParams.add(str[0].substring(p + 1, q - p - 1));
					p = q;
				}

				assert str[0].charAt(p + 1) == '}';
				str[0] = StrUtil.Remove(str[0], iStart[0], (p + 1) - iStart[0] + 1);
			}
			catch(Exception e)
			{
				str[0] = str[0].substring(0, iStart[0]);
			}

			if(bSprCmpParams && (ctx != null))
			{
				SprContext ctxSub = ctx.WithoutContentTransformations();
				for(int i = 0; i < lParams.size(); ++i)
					lParams.set(i, CompileInternal(lParams.get(i), ctxSub, uRecursionLevel));
			}

			return true;
		}

		private static String PerformTextTransforms(String strText, SprContext ctx,
			int uRecursionLevel)
		{
			String[] str = { strText };
			int[] iStart = new int[1];
			List<String> lParams = new ArrayList<String>();

			while(ParseAndRemovePlhWithParams(str, ctx, uRecursionLevel,
				"{T-REPLACE-RX:", iStart, lParams, true))
			{
				if(lParams.size() < 2) continue;
				if(lParams.size() == 2) lParams.add("");

				try
				{
					String strNew = lParams.get(0).replaceAll(lParams.get(1), lParams.get(2));
					strNew = TransformContent(strNew, ctx);
					str[0] = StrUtil.Insert(str[0], iStart[0], strNew);
				}
				catch(Exception e) { }
			}

			while(ParseAndRemovePlhWithParams(str, ctx, uRecursionLevel,
				"{T-CONV:", iStart, lParams, true))
			{
				if(lParams.size() < 2) continue;

				try
				{
					String strNew = lParams.get(0);
					String strCmd = lParams.get(1).toLowerCase();

					if(("u".equals(strCmd)) || ("upper".equals(strCmd)))
						strNew = strNew.toUpperCase();
					else if(("l".equals(strCmd)) || ("lower".equals(strCmd)))
						strNew = strNew.toLowerCase();
					else if("base64".equals(strCmd))
					{
						byte[] pbUtf8 = strNew.getBytes(StrUtil.Utf8);
						strNew = BaseEncoding.base64().encode(pbUtf8);
					}
					else if("hex".equals(strCmd))
					{
						byte[] pbUtf8 = strNew.getBytes(StrUtil.Utf8);
						strNew = MemUtil.ByteArrayToHexString(pbUtf8);
					}
					else if(Objects.equal(strCmd, "uri"))
						strNew = URLDecoder.decode(strNew, "utf-8");
					else if(Objects.equal(strCmd, "uri-dec"))
						strNew = URLEncoder.encode(strNew, "utf-8");

					strNew = TransformContent(strNew, ctx);
					str[0] = StrUtil.Insert(str[0], iStart[0], strNew);
				}
				catch(Exception e) { assert false; }
			}

			return str[0];
		}
            // Legacy, for backward compatibility only; see PickChars
            private static String ReplacePickPw(String strText, SprContext ctx,
                                                int uRecursionLevel)
            {
                if(ctx.getEntry() == null) { assert false; return strText; }

                String str = strText;

                while(true)
                {
                    final String strStart = "{PICKPASSWORDCHARS";

                    int iStart = str.toLowerCase().indexOf(strStart.toLowerCase());
                    if(iStart < 0) break;

                    int iEnd = str.indexOf('}', iStart);
                    if(iEnd < 0) break;

                    String strPlaceholder = str.substring(iStart, iEnd - iStart + 1);

                    String strParam = str.substring(iStart + strStart.length(),
                            iEnd - (iStart + strStart.length()));
                    String[] vParams = strParam.split(":");

                    int uCharCount = 0;
                    if(vParams.length >= 2) EntryUtil.parseInt(vParams[1]);

                    str = ReplacePickPwPlaceholder(str, strPlaceholder, uCharCount,
                            ctx, uRecursionLevel);
                }

                return str;
            }

            private static String ReplacePickPwPlaceholder(String str,
                                                           String strPlaceholder, int uCharCount, SprContext ctx,
                                                           int uRecursionLevel)
            {
                if(str.toLowerCase().indexOf(strPlaceholder.toLowerCase()) < 0) return str;

                ProtectedString ps = ctx.getEntry().getStrings().Get(PwDefs.PasswordField);
                if(ps != null)
                {
                    String strPassword = ps.ReadString();

                    String strPick = SprEngine.CompileInternal(strPassword,
                            ctx.WithoutContentTransformations(), uRecursionLevel + 1);

                    if(!Strings.isNullOrEmpty(strPick))
                    {
                        ProtectedString psPick = new ProtectedString(false, strPick);
                        String strPicked = "";

                        str = StrUtil.ReplaceCaseInsensitive(str, strPlaceholder,
                                SprEngine.TransformContent(strPicked, ctx));
                    }
                }

                return StrUtil.ReplaceCaseInsensitive(str, strPlaceholder, "");
            }

            private static String ReplacePickChars(String strText, SprContext ctx,
                                                   int uRecursionLevel)
            {
                if(ctx.getEntry() == null) return strText; // No assert

                String str = strText;

                Map<String, String> dPicked = new HashMap<String, String>();
                while(true)
                {
                    final String strStart = "{PICKCHARS";

                    int iStart = str.toLowerCase().indexOf(strStart.toLowerCase());
                    if(iStart < 0) break;

                    int iEnd = str.indexOf('}', iStart);
                    if(iEnd < 0) break;

                    String strPlaceholder = str.substring(iStart, iEnd - iStart + 1);

                    String strParam = str.substring(iStart + strStart.length(),
                            iEnd - (iStart + strStart.length()));

                    String strRep = "";
                    boolean bEncode = true;

                    if(strParam.length() == 0)
                        strRep = ShowCharPickDlg(ctx.getEntry().getStrings().ReadSafe(
                                PwDefs.PasswordField), 0, null, ctx, uRecursionLevel);
                    else if(strParam.startsWith(":"))
                    {
                        String strParams = strParam.substring(1);
                        String[] vParams = strParams.split(":");

                        String strField = "";
                        if(vParams.length >= 1) strField = Strings.nullToEmpty(vParams[0]).trim();
                        if(strField.length() == 0) strField = PwDefs.PasswordField;

                        String strOptions = "";
                        if(vParams.length >= 2) strOptions = Strings.nullToEmpty(vParams[1]);

                        Map<String, String> dOptions = new HashMap<String, String>();
                        String[] vOptions = Lists.newArrayList(Iterables.filter(
                                Lists.newArrayList(strOptions.split(",")),
                                new Predicate<String>() {
                                    @Override
                                    public boolean apply(String s) {
                                        return !Strings.isNullOrEmpty(s);
                                    }
                                })).toArray(new String[0]);
                        for(String strOption : vOptions)
                        {
                            String[] vKvp = strOption.split("=");
                            if(vKvp.length != 2) continue;

                            dOptions.put(vKvp[0].trim().toLowerCase(), vKvp[1].trim());
                        }

                        String strID = "";
                        if(dOptions.containsKey("id")) strID = dOptions.get("id").toLowerCase();

                        int uCharCount = 0;
                        if(dOptions.containsKey("c"))
                            uCharCount = EntryUtil.parseInt(dOptions.get("c"));
                        if(dOptions.containsKey("count"))
                            uCharCount = EntryUtil.parseInt(dOptions.get("count"));

                        Boolean bInitHide = null;
                        if(dOptions.containsKey("hide"))
                            bInitHide = StrUtil.StringToBool(dOptions.get("hide"));

                        String strContent = ctx.getEntry().getStrings().ReadSafe(strField);
                        if(strContent.length() == 0) { } // Leave strRep empty
                        else if((strID.length() > 0) && dPicked.containsKey(strID))
                            strRep = dPicked.get(strID);
                        else
                            strRep = ShowCharPickDlg(strContent, uCharCount, bInitHide,
                                    ctx, uRecursionLevel);

                        if(strID.length() > 0) dPicked.put(strID, strRep);

                        if(dOptions.containsKey("conv"))
                        {
                            int iOffset = 0;
                            if(dOptions.containsKey("conv-offset"))
                                iOffset = EntryUtil.parseInt(dOptions.get("conv-offset"));

                            String strConvFmt = "";
                            if(dOptions.containsKey("conv-fmt"))
                                strConvFmt = dOptions.get("conv-fmt");

                            String strConv = dOptions.get("conv");
                            if(strConv.equalsIgnoreCase("d"))
                            {
                                strRep = ConvertToDownArrows(strRep, iOffset, strConvFmt);
                                bEncode = false;
                            }
                        }
                    }

                    str = StrUtil.ReplaceCaseInsensitive(str, strPlaceholder,
                            bEncode ? SprEngine.TransformContent(strRep, ctx) : strRep);
                }

                return str;
            }

            private static String ShowCharPickDlg(String strWord, int uCharCount,
                                                  Boolean bInitHide, SprContext ctx, int uRecursionLevel)
            {
                String strPick = SprEngine.CompileInternal(strWord,
                        ctx.WithoutContentTransformations(), uRecursionLevel + 1);

                // No need to show the dialog when there's nothing to pick from
                // (this also prevents the dialog from showing up MaxRecursionDepth
                // times in case of a cyclic {PICKCHARS})
                if(Strings.isNullOrEmpty(strPick)) return "";

                ProtectedString psWord = new ProtectedString(false, strPick);
                return ""; // Don't transform here
            }

            private static String ConvertToDownArrows(String str, int iOffset,
                                                      String strLayout)
            {
                if(Strings.isNullOrEmpty(str)) return "";

                StringBuilder sb = new StringBuilder();
                for(int i = 0; i < str.length(); ++i)
                {
                    // if((sb.Length > 0) && !String.IsNullOrEmpty(strSep)) sb.Append(strSep);

                    char ch = str.charAt(i);

                    Integer iDowns = null;
                    if(strLayout.length() == 0)
                    {
                        if((ch >= '0') && (ch <= '9')) iDowns = (int)ch - '0';
                        else if((ch >= 'a') && (ch <= 'z')) iDowns = (int)ch - 'a';
                        else if((ch >= 'A') && (ch <= 'Z')) iDowns = (int)ch - 'A';
                    }
                    else if(strLayout.equalsIgnoreCase("0a"))
                    {
                        if((ch >= '0') && (ch <= '9')) iDowns = (int)ch - '0';
                        else if((ch >= 'a') && (ch <= 'z')) iDowns = (int)ch - 'a' + 10;
                        else if((ch >= 'A') && (ch <= 'Z')) iDowns = (int)ch - 'A' + 10;
                    }
                    else if(strLayout.equalsIgnoreCase("a0"))
                    {
                        if((ch >= '0') && (ch <= '9')) iDowns = (int)ch - '0' + 26;
                        else if((ch >= 'a') && (ch <= 'z')) iDowns = (int)ch - 'a';
                        else if((ch >= 'A') && (ch <= 'Z')) iDowns = (int)ch - 'A';
                    }
                    else if(strLayout.equalsIgnoreCase("1a"))
                    {
                        if((ch >= '1') && (ch <= '9')) iDowns = (int)ch - '1';
                        else if(ch == '0') iDowns = 9;
                        else if((ch >= 'a') && (ch <= 'z')) iDowns = (int)ch - 'a' + 10;
                        else if((ch >= 'A') && (ch <= 'Z')) iDowns = (int)ch - 'A' + 10;
                    }
                    else if(strLayout.equalsIgnoreCase("a1"))
                    {
                        if((ch >= '1') && (ch <= '9')) iDowns = (int)ch - '1' + 26;
                        else if(ch == '0') iDowns = 9 + 26;
                        else if((ch >= 'a') && (ch <= 'z')) iDowns = (int)ch - 'a';
                        else if((ch >= 'A') && (ch <= 'Z')) iDowns = (int)ch - 'A';
                    }

                    if(iDowns == null) continue;

                    for(int j = 0; j < (iOffset + iDowns); ++j) sb.append("{DOWN}");
                }

                return sb.toString();
            }

    }
