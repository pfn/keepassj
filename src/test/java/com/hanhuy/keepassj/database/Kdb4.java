package com.hanhuy.keepassj;
/*
 * Copyright 2010-2013 Brian Pellin.
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.awt.*;
import java.io.*;
import java.security.Security;

public class Kdb4 {
    @Test
	public void testSaving() throws IOException {
		InputStream is = Kdb4.class.getClassLoader().getResourceAsStream("test.kdbx");

        PwDatabase db = new PwDatabase();
        CompositeKey key = new CompositeKey();
        key.AddUserKey(new KcpPassword("12345"));
        db.setMasterKey(key);
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(is, KdbxFormat.Default, null);
		is.close();
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
        kdbx.Save(bos, db.getRootGroup(), KdbxFormat.Default, null);

		byte[] data = bos.toByteArray();
		
		InputStream bis = new ByteArrayInputStream(data);
        db = new PwDatabase();
        db.setMasterKey(key);
        kdbx = new KdbxFile(db);
        kdbx.Load(bis, KdbxFormat.Default, null);
		bis.close();
        Assert.assertEquals(7, db.getRootGroup().GetGroups(true).getUCount());
        Assert.assertEquals(112, db.getRootGroup().GetEntries(true).getUCount());
	}
	
    @Test
	public void testComposite() throws Exception {
		InputStream is = Kdb4.class.getClassLoader().getResourceAsStream("keyfile.kdbx");
        CompositeKey key = new CompositeKey();

        key.AddUserKey(new KcpPassword("12345"));
        key.AddUserKey(new KcpKeyFile(new File(Kdb4.class.getClassLoader().getResource("keyfile.key").toURI()).getAbsolutePath()));
        PwDatabase db = new PwDatabase();
        db.setMasterKey(key);
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(is, KdbxFormat.Default, null);
		is.close();
		
	}

    @Test
	public void testKeyfile() throws Exception {
        InputStream is = Kdb4.class.getClassLoader().getResourceAsStream("key-only.kdbx");
        CompositeKey key = new CompositeKey();

        key.AddUserKey(new KcpKeyFile(new File(Kdb4.class.getClassLoader().getResource("keyfile.key").toURI()).getAbsolutePath()));
        PwDatabase db = new PwDatabase();
        db.setMasterKey(key);
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(is, KdbxFormat.Default, null);
        is.close();
	}

    @Test
    public void testV1Keyfile() throws Exception {
        InputStream is = Kdb4.class.getClassLoader().getResourceAsStream("Old_Key_Sample.kdbx");
        CompositeKey key = new CompositeKey();

        key.AddUserKey(new KcpPassword("password1"));
        key.AddUserKey(new KcpKeyFile(new File(Kdb4.class.getClassLoader().getResource("Old_Key.key").toURI()).getAbsolutePath()));
        PwDatabase db = new PwDatabase();
        db.setMasterKey(key);
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(is, KdbxFormat.Default, null);
        is.close();
    }

    @Test
	public void testNoGzip() throws IOException {
        InputStream is = Kdb4.class.getClassLoader().getResourceAsStream("no-encrypt.kdbx");

        PwDatabase db = new PwDatabase();
        CompositeKey key = new CompositeKey();
        key.AddUserKey(new KcpPassword("12345"));
        db.setMasterKey(key);
        KdbxFile kdbx = new KdbxFile(db);
        kdbx.Load(is, KdbxFormat.Default, null);
        is.close();
	}
	
}
