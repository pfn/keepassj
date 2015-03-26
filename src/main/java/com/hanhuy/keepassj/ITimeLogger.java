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
	/// Interface for objects that support various times (creation time, last
	/// access time, last modification time and expiry time). Offers
	/// several helper functions (for example a function to touch the current
	/// object).
	/// </summary>
	public interface ITimeLogger
	{
		/// <summary>
		/// The date/time when the object was created.
		/// </summary>
		public Date getCreationTime();
        public void setCreationTime(Date d);

		/// <summary>
		/// The date/time when the object was last modified.
		/// </summary>
		public Date getLastModificationTime();
        public void setLastModificationTime(Date date);

		/// <summary>
		/// The date/time when the object was last accessed.
		/// </summary>
		public Date getLastAccessTime();
		public void setLastAccessTime(Date d);

		/// <summary>
		/// The date/time when the object expires.
		/// </summary>
		public Date getExpiryTime();
		public void setExpiryTime(Date d);

		/// <summary>
		/// Flag that determines if the object does expire.
		/// </summary>
		public boolean getExpires();
		public void setExpires(boolean b);

		/// <summary>
		/// Get or set the usage count of the object. To increase the usage
		/// count by one, use the <c>Touch</c> function.
		/// </summary>
		public long getUsageCount();
		public void setUsageCount(long c);

		/// <summary>
		/// The date/time when the location of the object was last changed.
		/// </summary>
		public Date getLocationChanged();
		public void setLocationChanged(Date d);

		/// <summary>
		/// Touch the object. This function updates the internal last access
		/// time. If the <paramref name="bModified" /> parameter is <c>true</c>,
		/// the last modification time gets updated, too. Each time you call
		/// <c>Touch</c>, the usage count of the object is increased by one.
		/// </summary>
		/// <param name="bModified">Update last modification time.</param>
		public void Touch(boolean bModified);
	}
