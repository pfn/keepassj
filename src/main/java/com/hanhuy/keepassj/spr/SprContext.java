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

import com.hanhuy.keepassj.PwDatabase;
import com.hanhuy.keepassj.PwEntry;

import java.util.EventObject;
import java.util.HashMap;
import java.util.Map;

public class SprContext implements Cloneable
	{
		private PwEntry m_pe = null;
		public PwEntry getEntry()
		{
			return m_pe;
		}
        public void setEntry(PwEntry value) { m_pe = value; }

		private PwDatabase m_pd = null;
		public PwDatabase getDatabase()
		{
			return m_pd;
		}
        public void setDatabase(PwDatabase value) { m_pd = value; }

		private String m_strBase = null;
		/// <summary>
		/// The parent String, like e.g. the input String before any
		/// override has been applied.
		/// </summary>
		public String getBase()
		{
			return m_strBase;
		}
        public void setBase(String value) { m_strBase = value; }

		private boolean m_bBaseIsEnc = false;
		/// <summary>
		/// Specifies whether <c>Base</c> has been content-transformed already.
		/// </summary>
		public boolean getBaseIsEncoded()
		{
			return m_bBaseIsEnc;
		}
        public void setBaseIsEncoded(boolean value) { m_bBaseIsEnc = value; }

		private boolean m_bMakeAT = false;
		public boolean getEncodeAsAutoTypeSequence()
		{
			return m_bMakeAT;
		}
        public void setEncodeAsAutoTypeSequence(boolean value) { m_bMakeAT = value; }

		private boolean m_bMakeCmdQuotes = false;
		public boolean getEncodeQuotesForCommandLine()
		{
			return m_bMakeCmdQuotes;
		}
        public void setEncodeQuotesForCommandLine(boolean value) { m_bMakeCmdQuotes = value; }

		private boolean m_bForcePlainTextPasswords = true;
		public boolean getForcePlainTextPasswords()
		{
			return m_bForcePlainTextPasswords;
		}
        public void setForcePlainTextPasswords(boolean value) { m_bForcePlainTextPasswords = value; }

		private SprCompileFlags.Flags m_flags = SprCompileFlags.All.flags;
		public SprCompileFlags.Flags getFlags()
		{
			return m_flags;
		}
        public void setFlags(SprCompileFlags.Flags value) { m_flags = value; }

		private SprRefsCache m_refsCache = new SprRefsCache();
		/// <summary>
		/// Used internally by <c>SprEngine</c>; don't modify it.
		/// </summary>
		SprRefsCache getRefsCache()
		{
			return m_refsCache;
		}

		// private boolean m_bNoUrlSchemeOnce = false;
		// /// <summary>
		// /// Used internally by <c>SprEngine</c>; don't modify it.
		// /// </summary>
		// boolean UrlRemoveSchemeOnce
		// {
		//	get { return m_bNoUrlSchemeOnce; }
		//	set { m_bNoUrlSchemeOnce = value; }
		// }

		public SprContext() { }

		public SprContext(PwEntry pe, PwDatabase pd, SprCompileFlags.Flags fl)
		{
			Init(pe, pd, false, false, fl);
		}

		public SprContext(PwEntry pe, PwDatabase pd, SprCompileFlags.Flags fl,
			boolean bEncodeAsAutoTypeSequence, boolean bEncodeQuotesForCommandLine)
		{
			Init(pe, pd, bEncodeAsAutoTypeSequence, bEncodeQuotesForCommandLine, fl);
		}

		private void Init(PwEntry pe, PwDatabase pd, boolean bAT, boolean bCmdQuotes,
			SprCompileFlags.Flags fl)
		{
			m_pe = pe;
			m_pd = pd;
			m_bMakeAT = bAT;
			m_bMakeCmdQuotes = bCmdQuotes;
			m_flags = fl;
		}

		public SprContext clone()
		{
            try {
                return (SprContext)super.clone();
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

		/// <summary>
		/// Used by <c>SprEngine</c> internally; do not use.
		/// </summary>
		SprContext WithoutContentTransformations()
		{
			SprContext ctx = clone();

			ctx.m_bMakeAT = false;
			ctx.m_bMakeCmdQuotes = false;
			// ctx.m_bNoUrlSchemeOnce = false;

			return ctx;
		}
	}


class SprRefsCache extends HashMap<String,String> {
    public SprRefsCache(int initialCapacity, float loadFactor) {
        super(initialCapacity, loadFactor);
    }

    public SprRefsCache(int initialCapacity) {
        super(initialCapacity);
    }

    public SprRefsCache() {
    }

    public SprRefsCache(Map<? extends String, ? extends String> m) {
        super(m);
    }
}
