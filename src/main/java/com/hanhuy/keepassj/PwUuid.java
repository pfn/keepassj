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

import java.nio.ByteBuffer;
import java.util.UUID;

// [ImmutableObject(true)]
	/// <summary>
	/// Represents an UUID of a password entry or group. Once created,
	/// <c>PwUuid</c> objects aren't modifyable anymore (immutable).
	/// </summary>
	public class PwUuid implements Comparable<PwUuid>
	{
		/// <summary>
		/// Standard size in bytes of a UUID.
		/// </summary>
		public final static int UuidSize = 16;

		/// <summary>
		/// Zero UUID (all bytes are zero).
		/// </summary>
		public static final PwUuid Zero = new PwUuid(false);

		private byte[] m_pbUuid = null; // Never null after constructor

		/// <summary>
		/// Get the 16 UUID bytes.
		/// </summary>
		public byte[] getUuidBytes()
		{
			return m_pbUuid;
		}

		/// <summary>
		/// Construct a new UUID object.
		/// </summary>
		/// <param name="bCreateNew">If this parameter is <c>true</c>, a new
		/// UUID is generated. If it is <c>false</c>, the UUID is initialized
		/// to zero.</param>
		public PwUuid(boolean bCreateNew)
		{
			if(bCreateNew) CreateNew();
			else SetZero();
		}

		/// <summary>
		/// Construct a new UUID object.
		/// </summary>
		/// <param name="uuidBytes">Initial value of the <c>PwUuid</c> object.</param>
		public PwUuid(byte[] uuidBytes)
		{
			SetValue(uuidBytes);
		}

		/// <summary>
		/// Create a new, random UUID.
		/// </summary>
		/// <returns>Returns <c>true</c> if a random UUID has been generated,
		/// otherwise it returns <c>false</c>.</returns>
		private void CreateNew()
		{
			assert m_pbUuid == null; // Only call from constructor
			while(true)
			{
				m_pbUuid = new byte[16];
                ByteBuffer b = ByteBuffer.wrap(m_pbUuid);
                UUID uuid = UUID.randomUUID();
                b.putLong(uuid.getMostSignificantBits());
                b.putLong(uuid.getLeastSignificantBits());

				if((m_pbUuid == null) || (m_pbUuid.length != UuidSize))
				{
					assert false;
					throw new UnsupportedOperationException();
				}

				// Zero is a reserved value -- do not generate Zero
				if(!Equals(PwUuid.Zero)) break;
				assert false;
			}
		}

		private void SetValue(byte[] uuidBytes)
		{
			assert (uuidBytes != null) && (uuidBytes.length == UuidSize);
			if(uuidBytes == null) throw new IllegalArgumentException("uuidBytes");
			if(uuidBytes.length != (int)UuidSize) throw new IllegalArgumentException();

			assert m_pbUuid == null; // Only call from constructor
			m_pbUuid = new byte[UuidSize];

			System.arraycopy(uuidBytes, 0, m_pbUuid, 0, UuidSize);
		}

		private void SetZero()
		{
			assert m_pbUuid == null; // Only call from constructor
			m_pbUuid = new byte[UuidSize];

			// Array.Clear(m_pbUuid, 0, (int)UuidSize);
if (false) // debug
{
			//List<byte> l = new List<byte>(m_pbUuid);
			//assert l.TrueForAll(bt => (bt == 0));
}
		}

		@Deprecated
		public boolean EqualsValue(PwUuid uuid)
		{
			return Equals(uuid);
		}

        @Override
		public boolean equals(Object obj)
		{
            if (obj instanceof PwUuid)
                return Equals((PwUuid) obj);
			return false;
		}

		public boolean Equals(PwUuid other)
		{
			if(other == null) { assert false; return false; }

			for(int i = 0; i < (int)UuidSize; ++i)
			{
				if(m_pbUuid[i] != other.m_pbUuid[i]) return false;
			}

			return true;
		}

		private int m_h = 0;
        @Override
		public int hashCode()
		{
			if(m_h == 0)
				m_h = (int)MemUtil.Hash32(m_pbUuid, 0, m_pbUuid.length);
			return m_h;
		}

		public int compareTo(PwUuid other)
		{
			if(other == null)
			{
				assert false;
				throw new IllegalArgumentException("other");
			}

			for(int i = 0; i < (int)UuidSize; ++i)
			{
				if(m_pbUuid[i] < other.m_pbUuid[i]) return -1;
				if(m_pbUuid[i] > other.m_pbUuid[i]) return 1;
			}

			return 0;
		}

		/// <summary>
		/// Convert the UUID to its String representation.
		/// </summary>
		/// <returns>String containing the UUID value.</returns>
		public String ToHexString()
		{
			return MemUtil.ByteArrayToHexString(m_pbUuid);
		}
	}

	@Deprecated
	class PwUuidComparable implements Comparable<PwUuidComparable>
	{
		private byte[] m_pbUuid = new byte[PwUuid.UuidSize];

		public PwUuidComparable(PwUuid pwUuid)
		{
			if(pwUuid == null) throw new IllegalArgumentException("pwUuid");

			System.arraycopy(pwUuid.getUuidBytes(), 0, m_pbUuid, 0, PwUuid.UuidSize);
		}

		public int compareTo(PwUuidComparable other)
		{
			if(other == null) throw new IllegalArgumentException("other");

			for(int i = 0; i < (int)PwUuid.UuidSize; ++i)
			{
				if(m_pbUuid[i] < other.m_pbUuid[i]) return -1;
				if(m_pbUuid[i] > other.m_pbUuid[i]) return 1;
			}

			return 0;
		}
	}
