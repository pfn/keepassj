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

import java.util.EventObject;

/// <summary>
	/// Function definition of a method that performs an action on a group.
	/// When traversing the internal tree, this function will be invoked
	/// for all visited groups.
	/// </summary>
	/// <param name="pg">Currently visited group.</param>
	/// <returns>You must return <c>true</c> if you want to continue the
	/// traversal. If you want to immediately stop the whole traversal,
	/// return <c>false</c>.</returns>
	interface GroupHandler {
        public boolean delegate(PwGroup pg);
    }

	/// <summary>
	/// Function definition of a method that performs an action on an entry.
	/// When traversing the internal tree, this function will be invoked
	/// for all visited entries.
	/// </summary>
	/// <param name="pe">Currently visited entry.</param>
	/// <returns>You must return <c>true</c> if you want to continue the
	/// traversal. If you want to immediately stop the whole traversal,
	/// return <c>false</c>.</returns>
	interface EntryHandler {
        public boolean delegate(PwEntry pe);
    }

	interface VoidDelegate {
        public void delegate();
    }

	interface StrPwEntryDelegate {
        public String delegate(String str, PwEntry pe);
    }
