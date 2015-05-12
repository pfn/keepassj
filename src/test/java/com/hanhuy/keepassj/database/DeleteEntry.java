package com.hanhuy.keepassj.database;
/*
 * Copyright 2009 Brian Pellin.
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

import com.hanhuy.keepassj.*;
import org.junit.Test;

import static org.junit.Assert.*;

import java.util.List;

public class DeleteEntry {
	private static final String GROUP1_NAME = "General";
	private static final String ENTRY1_NAME = "ba842191-c613-4cbb-b5cc-bdf4b61dd235";
	private static final String ENTRY2_NAME = "8e117b5c-33ee-4ea5-8ed5-3f4064d69ac2";
	private static final String KEYFILE = "";
	private static final String PASSWORD = "12345";
	private static final String ASSET = "test.kdbx";

    @Test
	public void testDelete() throws Exception {

		PwDatabase db;

        db = TestData.GetDb(ASSET, PASSWORD, KEYFILE);

		PwGroup group1 = getGroup(db, GROUP1_NAME);
		assertNotNull("Could not find group1", group1);

		// Delete the group
        group1.getParentGroup().getGroups().Remove(group1);

		// Verify the entries were deleted
		PwEntry entry1 = getEntry(db, ENTRY1_NAME);
		assertNull("Entry 1 was not removed", entry1);

		PwEntry entry2 = getEntry(db, ENTRY2_NAME);
		assertNull("Entry 2 was not removed", entry2);

		// Verify the entries were removed from the search index
		// Verify the group was deleted
		group1 = getGroup(db, GROUP1_NAME);
		assertNull("Group 1 was not removed.", group1);
	}

	@Test
	public void testEntryDelete() throws Exception {
		PwDatabase db = TestData.GetDb(ASSET, PASSWORD, KEYFILE);
		PwEntry entry = getEntry(db, ENTRY1_NAME);
		assertNotNull(entry);
		PwGroup recycle = db.getRootGroup().FindGroup(db.getRecycleBinUuid(), true);
		assertTrue(db.isRecycleBinEnabled());
		assertNotNull(recycle);
	}

	private PwEntry getEntry(PwDatabase pm, String name) {
		PwObjectList<PwEntry> entries = pm.getRootGroup().GetEntries(true);
		for ( int i = 0; i < entries.getUCount(); i++ ) {
			PwEntry entry = entries.GetAt(i);
			if ( entry.getStrings().ReadSafe(PwDefs.TitleField).equals(name) ) {
				return entry;
			}
		}

		return null;

	}

	private PwGroup getGroup(PwDatabase pm, String name) {
		PwObjectList<PwGroup> groups = pm.getRootGroup().GetGroups(true);
		for ( int i = 0; i < groups.getUCount(); i++ ) {
			PwGroup group = groups.GetAt(i);
			if ( group.getName().equals(name) ) {
				return group;
			}
		}

		return null;
	}


}
