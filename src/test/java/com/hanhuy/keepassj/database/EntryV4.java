/*
 * Copyright 2013 Brian Pellin.
 *     
 * This file is part of KeePassDroid.
 *
 *  KeePassDroid is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDroid is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.hanhuy.keepassj.database;

import com.hanhuy.keepassj.ProtectedString;
import com.hanhuy.keepassj.PwDatabase;
import com.hanhuy.keepassj.PwDefs;
import com.hanhuy.keepassj.PwEntry;
import junit.framework.TestCase;

public class EntryV4 extends TestCase {

	public void testBackup() {
		PwDatabase db = new PwDatabase();
		
		db.setHistoryMaxItems(2);
		
		PwEntry entry = new PwEntry(true, true);
        entry.getStrings().Set(PwDefs.TitleField, new ProtectedString(false, "Title1"));
        entry.getStrings().Set(PwDefs.UserNameField, new ProtectedString(true, "User1"));
        entry.CreateBackup(db);

        entry.getStrings().Set(PwDefs.TitleField, new ProtectedString(false, "Title2"));
        entry.getStrings().Set(PwDefs.UserNameField, new ProtectedString(true, "User2"));
		entry.CreateBackup(db);

        entry.getStrings().Set(PwDefs.TitleField, new ProtectedString(false, "Title3"));
        entry.getStrings().Set(PwDefs.UserNameField, new ProtectedString(true, "User3"));
		entry.CreateBackup(db);
		
		PwEntry backup = entry.getHistory().GetAt(0);
		assertEquals("Title2", backup.getStrings().ReadSafe(PwDefs.TitleField));
		assertEquals("User2", backup.getStrings().ReadSafe(PwDefs.UserNameField));
	}

}
