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

import com.google.common.base.Strings;
import com.hanhuy.keepassj.*;

import java.io.InputStream;

public class TestData {
	private static final String TEST1_KEYFILE = "";
	private static final String TEST1_KDB = "test1.kdb";
	private static final String TEST1_PASSWORD = "12345";
    private static final String TEST_KDBX = "test.kdbx";

	private static PwDatabase mDb1;

	
	public static PwDatabase GetDb1() throws Exception {
		return GetDb1(false);
	}
	
	public static PwDatabase GetDb2(boolean forceReload) throws Exception {
		if ( mDb1 == null || forceReload ) {
			mDb1 = GetDb(TEST1_KDB, TEST1_PASSWORD, TEST1_KEYFILE);
		}
		
		return mDb1;
	}
    public static PwDatabase GetDb1(boolean forceReload) throws Exception {
        if ( mDb1 == null || forceReload ) {
            mDb1 = GetDb(TEST_KDBX, TEST1_PASSWORD, TEST1_KEYFILE);
        }

        return mDb1;
    }

	public static PwDatabase GetDb(String asset, String password, String keyfile) throws Exception {
		InputStream is = TestData.class.getClassLoader().getResourceAsStream(asset);

		PwDatabase Db = new PwDatabase();
        CompositeKey key = new CompositeKey();
        key.AddUserKey(new KcpPassword(password));
        if (!Strings.isNullOrEmpty(keyfile)) {
            key.AddUserKey(new KcpKeyFile(keyfile));
        }
        Db.setMasterKey(key);
        KdbxFile file = new KdbxFile(Db);
        file.Load(is, KdbxFormat.Default, null);
		return Db;
	}

	public static PwDatabase GetTest2() throws Exception {
		if ( mDb1 == null ) {
			GetDb1();
		}
		
		return mDb1;
	}

    public static PwDatabase GetTest1() throws Exception {
        return GetDb(TEST_KDBX, TEST1_PASSWORD, TEST1_KEYFILE);
    }
}
