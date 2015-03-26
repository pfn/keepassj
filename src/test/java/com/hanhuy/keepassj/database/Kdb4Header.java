/*
 * Copyright 2010 Brian Pellin.
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

import java.io.InputStream;

import com.hanhuy.keepassj.*;
import org.junit.Assert;
import org.junit.Test;

public class Kdb4Header {
    @Test
	public void testReadHeader() throws Exception {
		InputStream is = Kdb4Header.class.getClassLoader().getResourceAsStream("test.kdbx");
        CompositeKey key = new CompositeKey();
        key.AddUserKey(new KcpPassword("12345"));
        PwDatabase db = new PwDatabase();
        db.setMasterKey(key);
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(is, KdbxFormat.Default, null);
        Assert.assertEquals(6000, db.getKeyEncryptionRounds());
		

		Assert.assertEquals(db.getDataCipherUuid(), StandardAesEngine.getAesUuid());
		
		is.close();

	}
}
