/*
 * Copyright 2014 Brian Pellin.
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

import com.google.common.io.BaseEncoding;
import com.hanhuy.keepassj.PwDatabase;
import com.hanhuy.keepassj.PwEntry;
import com.hanhuy.keepassj.PwUuid;
import com.hanhuy.keepassj.spr.SprCompileFlags;
import com.hanhuy.keepassj.spr.SprContext;
import com.hanhuy.keepassj.spr.SprEngine;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.util.UUID;

public class SprEngineTest {
	private static PwDatabase db;

    @BeforeClass
	public static void setUp() throws Exception {
		db = TestData.GetDb1();
	}

    private final String REFID = "2B1D56590D961F48A8CE8C392CE6CD35";
	private final String REF = "{REF:P@I:2B1D56590D961F48A8CE8C392CE6CD35}";
	private final String ENCODE_UUID = "IN7RkON49Ui1UZ2ddqmLcw==";
	private final String RESULT = "Password";
    @Test public void findReferenced() {
        PwUuid uuid = new PwUuid(BaseEncoding.base16().decode(REFID));
        PwEntry entry = db.getRootGroup().FindEntry(uuid, true);
        assertNotNull(entry);
    }
    @Test
	public void testRefReplace() {
		PwUuid entryUUID = decodeUUID(ENCODE_UUID);
		
		PwEntry entry = db.getRootGroup().FindEntry(entryUUID, true);
        SprContext ctx = new SprContext(entry, db, SprCompileFlags.All.flags, false, false);
        assertNotNull(entry);
		assertEquals(RESULT, SprEngine.Compile(REF, ctx));

	}
	
	private PwUuid decodeUUID(String encoded) {
		if (encoded == null || encoded.length() == 0 ) {
			return PwUuid.Zero;
		}
		
		byte[] buf = BaseEncoding.base64().decode(encoded);
		return new PwUuid(buf);
	}

}
