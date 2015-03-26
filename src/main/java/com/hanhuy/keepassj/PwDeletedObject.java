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

import java.util.Date;

	/// <summary>
	/// Represents an object that has been deleted.
	/// </summary>
	public class PwDeletedObject implements IDeepCloneable<PwDeletedObject>
	{
		private PwUuid m_uuid = PwUuid.Zero;
		/// <summary>
		/// UUID of the entry that has been deleted.
		/// </summary>
		public PwUuid getUuid()
		{
			return m_uuid;
		}
			public void setUuid(PwUuid value)
			{
				if(value == null) throw new IllegalArgumentException("value");
				m_uuid = value;
			}

		private Date m_dtDeletionTime = PwDefs.DtDefaultNow;
		/// <summary>
		/// The date/time when the entry has been deleted.
		/// </summary>
		public Date getDeletionTime()
		{
			return m_dtDeletionTime;
		}
			public void setDeletionTime(Date value) { m_dtDeletionTime = value; }

		/// <summary>
		/// Construct a new <c>PwDeletedObject</c> object.
		/// </summary>
		public PwDeletedObject()
		{
		}

		public PwDeletedObject(PwUuid uuid, Date dtDeletionTime)
		{
			if(uuid == null) throw new IllegalArgumentException("uuid");

			m_uuid = uuid;
			m_dtDeletionTime = dtDeletionTime;
		}

		/// <summary>
		/// Clone the object.
		/// </summary>
		/// <returns>Value copy of the current object.</returns>
		public PwDeletedObject CloneDeep()
		{
			PwDeletedObject pdo = new PwDeletedObject();

			pdo.m_uuid = m_uuid; // PwUuid objects are immutable
			pdo.m_dtDeletionTime = m_dtDeletionTime;

			return pdo;
		}
	}
