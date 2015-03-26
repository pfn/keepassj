package com.hanhuy.keepassj;
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

import com.hanhuy.keepassj.database.TestData;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;

public class PwEntryTestV3 {
	static PwEntry mPE;
	
	@BeforeClass
	public static void setUp() throws Exception {
		mPE = (PwEntry) TestData.GetTest1().getRootGroup().GetEntries(true).GetAt(0);
	}

    @Test
	public void testName() {
		assertTrue("Name was " + mPE.getStrings().ReadSafe(PwDefs.TitleField), mPE.getStrings().ReadSafe(PwDefs.TitleField).equals("Sample Entry"));
	}

    @Test
	public void testPassword() throws Exception {
		String sPass = "98ae7c52-f11f-441b-a760-0e1eeced5937";

        PwEntry entry = (PwEntry) TestData.GetTest1().getRootGroup().GetEntries(true).GetAt(1);
        assertEquals(sPass, entry.getStrings().ReadSafe(PwDefs.PasswordField));
	}

    @Test
	public void testCreation() {
		Calendar cal = Calendar.getInstance();
		cal.setTime(mPE.getCreationTime());
		
		assertEquals("Incorrect year.", cal.get(Calendar.YEAR), 2010);
		assertEquals("Incorrect month.", cal.get(Calendar.MONTH), 3);
		assertEquals("Incorrect day.", cal.get(Calendar.DAY_OF_MONTH), 22);
	}
}
