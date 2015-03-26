package com.hanhuy.keepassj.search;
/*
* Copyright 2009-2011 Brian Pellin.
*
* This file is part of KeePassDroid.
*
* KeePassDroid is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* KeePassDroid is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with KeePassDroid. If not, see <http://www.gnu.org/licenses/>.
*
*/

import com.hanhuy.keepassj.*;
import com.hanhuy.keepassj.database.TestData;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

public class SearchTest {
	
	private static PwDatabase mDb;
	
	@BeforeClass
	public static void setUp() throws Exception {
	    mDb = TestData.GetDb1(true);
	}

    @Test
	public void testSearch() {
		PwObjectList<PwEntry> results = search("Sample");
		assertEquals("Search result not found.", 1, results.getUCount());
	}

    @Test
    public void searchExpectAll() {
        PwObjectList<PwEntry> results = search("");
        assertEquals("Search result not found.", 112, results.getUCount());
    }

	public void testBackupIncluded() {
		PwObjectList<PwEntry> results = search("BackupOnly");
		
		assertTrue("Search result not found.", results.getUCount() > 0);
	}

	public void testBackupExcluded() {
		PwObjectList<PwEntry> results = search("BackupOnly");
		
		assertFalse("Search result found, but should not have been.", results.getUCount() > 0);
	}

    private PwObjectList<PwEntry> search(String s) {
        SearchParameters sp = new SearchParameters();
        sp.setSearchString(s);
        PwObjectList<PwEntry> results = new PwObjectList<PwEntry>();
        mDb.getRootGroup().SearchEntries(sp, results);
        return results;
    }
}
