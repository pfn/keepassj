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
import java.util.List;

/// <summary>
	/// Pool of encryption/decryption algorithms (ciphers).
	/// </summary>
	public class CipherPool
	{
		private List<ICipherEngine> m_vCiphers = new ArrayList<ICipherEngine>();
		private static CipherPool m_poolGlobal = null;

		/// <summary>
		/// Reference to the global cipher pool.
		/// </summary>
		public static CipherPool getGlobalPool()
		{
				if(m_poolGlobal != null) return m_poolGlobal;

				m_poolGlobal = new CipherPool();
				m_poolGlobal.AddCipher(new StandardAesEngine());

				return m_poolGlobal;
		}

		/// <summary>
		/// Remove all cipher engines from the current pool.
		/// </summary>
		public void Clear()
		{
			m_vCiphers.clear();
		}

		/// <summary>
		/// Add a cipher engine to the pool.
		/// </summary>
		/// <param name="csEngine">Cipher engine to add. Must not be <c>null</c>.</param>
		public void AddCipher(ICipherEngine csEngine)
		{
			assert csEngine != null;
			if(csEngine == null) throw new IllegalArgumentException("csEngine");

			// Return if a cipher with that ID is registered already.
			for(int i = 0; i < m_vCiphers.size(); ++i)
				if(m_vCiphers.get(i).getCipherUuid().Equals(csEngine.getCipherUuid()))
					return;

			m_vCiphers.add(csEngine);
		}

		/// <summary>
		/// Get a cipher identified by its UUID.
		/// </summary>
		/// <param name="uuidCipher">UUID of the cipher to return.</param>
		/// <returns>Reference to the requested cipher. If the cipher is
		/// not found, <c>null</c> is returned.</returns>
		public ICipherEngine GetCipher(PwUuid uuidCipher)
		{
			for(ICipherEngine iEngine : m_vCiphers)
			{
				if(iEngine.getCipherUuid().Equals(uuidCipher))
					return iEngine;
			}

			return null;
		}

		/// <summary>
		/// Get the index of a cipher. This index is temporary and should
		/// not be stored or used to identify a cipher.
		/// </summary>
		/// <param name="uuidCipher">UUID of the cipher.</param>
		/// <returns>Index of the requested cipher. Returns <c>-1</c> if
		/// the specified cipher is not found.</returns>
		public int GetCipherIndex(PwUuid uuidCipher)
		{
			for(int i = 0; i < m_vCiphers.size(); ++i)
			{
				if(m_vCiphers.get(i).getCipherUuid().Equals(uuidCipher))
					return i;
			}

			assert false;
			return -1;
		}

		/// <summary>
		/// Get the index of a cipher. This index is temporary and should
		/// not be stored or used to identify a cipher.
		/// </summary>
		/// <param name="strDisplayName">Name of the cipher. Note that
		/// multiple ciphers can have the same name. In this case, the
		/// first matching cipher is returned.</param>
		/// <returns>Cipher with the specified name or <c>-1</c> if
		/// no cipher with that name is found.</returns>
		public int GetCipherIndex(String strDisplayName)
		{
			for(int i = 0; i < m_vCiphers.size(); ++i)
				if(m_vCiphers.get(i).getDisplayName() == strDisplayName)
					return i;

			assert false;
			return -1;
		}

		/// <summary>
		/// Get the number of cipher engines in this pool.
		/// </summary>
		public int getEngineCount()
		{
			return m_vCiphers.size();
		}

		/// <summary>
		/// Get the cipher engine at the specified position. Throws
		/// an exception if the index is invalid. You can use this
		/// to iterate over all ciphers, but do not use it to
		/// identify ciphers.
		/// </summary>
		/// <param name="nIndex">Index of the requested cipher engine.</param>
		/// <returns>Reference to the cipher engine at the specified
		/// position.</returns>
		public ICipherEngine get(int nIndex)
		{
				if((nIndex < 0) || (nIndex >= m_vCiphers.size()))
					throw new ArrayIndexOutOfBoundsException("nIndex");

				return m_vCiphers.get(nIndex);
		}
	}
