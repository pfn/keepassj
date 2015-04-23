package com.hanhuy.keepassj.database;

import com.hanhuy.keepassj.*;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;

/**
 * @author pfnguyen
 */
public class DatabaseModificationTest {

    @Test
    public void saveAndReloadDatabase() throws Exception {
        PwDatabase db = TestData.GetDb1();
        KdbxFile file = new KdbxFile(db);
        File f = File.createTempFile("keepassj-test", ".kdbx");
        f.deleteOnExit();
        long mtime = f.lastModified();
        FileOutputStream fout = new FileOutputStream(f);
        try {
            file.Save(fout, db.getRootGroup(), KdbxFormat.Default, null);
        } finally {
            fout.close();
        }
        PwDatabase db2 = TestData.GetDb(f, TestData.TEST1_PASSWORD, TestData.TEST1_KEYFILE);
        Assert.assertEquals(db.getRootGroup().GetEntries(true).getUCount(),
                db2.getRootGroup().GetEntries(true).getUCount());
        Assert.assertEquals(db.getRootGroup().getUuid(),
                db2.getRootGroup().getUuid());
        db2.Save(null);
        Assert.assertThat(f.lastModified(), Matchers.greaterThan(mtime));
        db2.Close();
        db2 = TestData.GetDb(f, TestData.TEST1_PASSWORD, TestData.TEST1_KEYFILE);
        Assert.assertEquals(db.getRootGroup().GetEntries(true).getUCount(),
                db2.getRootGroup().GetEntries(true).getUCount());
        Assert.assertEquals(db.getRootGroup().getUuid(),
                db2.getRootGroup().getUuid());
        f.delete();
    }

    @Test
    public void changeMasterKey() throws Exception {

        PwDatabase db = TestData.GetDb1();

        File f = File.createTempFile("keepassj-test", ".kdbx");
        long mtime = f.lastModified();
        db.SaveAs(IOConnectionInfo.FromPath(f.getAbsolutePath()), true, null);
        Assert.assertThat(f.lastModified(), Matchers.greaterThan(mtime));
        f.deleteOnExit();
        Assert.assertTrue(db.getRootGroup().GetEntries(true).getUCount() > 0);
        CompositeKey newKey = new CompositeKey();
        db.setMasterKey(newKey);

        File f2 = File.createTempFile("keepassj-test", ".kdbx");
        db.SaveAs(IOConnectionInfo.FromPath(f2.getAbsolutePath()), false, null);
        PwDatabase db2 = new PwDatabase();
        f2.deleteOnExit();
        db2.Open(IOConnectionInfo.FromPath(f2.getAbsolutePath()), newKey, null);
        Assert.assertEquals(db.getRootGroup().GetEntries(true).getUCount(),
                db2.getRootGroup().GetEntries(true).getUCount());
        Assert.assertEquals(db.getRootGroup().getUuid(),
                db2.getRootGroup().getUuid());
        CompositeKey newPassword = new CompositeKey();
        newPassword.AddUserKey(new KcpPassword("new password phrase long long long"));
        db2.setMasterKey(newPassword);

        File f3 = File.createTempFile("keepassj-test", ".kdbx");
        f3.deleteOnExit();
        db2.SaveAs(IOConnectionInfo.FromPath(f3.getAbsolutePath()), false, null);
        PwDatabase db3 = new PwDatabase();
        try {
            db3.Open(IOConnectionInfo.FromPath(f3.getAbsolutePath()), newKey, null);
            Assert.fail("should not be able to open with blank key");
        } catch (RuntimeException e) {
            Assert.assertTrue("should be InvalidCompositeKey", e.getCause() instanceof KdbxFileFormatException);
            KdbxFileFormatException ex = (KdbxFileFormatException) e.getCause();
            Assert.assertTrue("should be InvalidCompositeKey", ex.getCause() instanceof InvalidCompositeKeyException);
        }
        db3.Open(IOConnectionInfo.FromPath(f3.getAbsolutePath()), newPassword, null);
        Assert.assertEquals(db.getRootGroup().GetEntries(true).getUCount(),
                db3.getRootGroup().GetEntries(true).getUCount());
        Assert.assertEquals(db.getRootGroup().getUuid(),
                db3.getRootGroup().getUuid());

        f.delete();
        f2.delete();
        f3.delete();
    }
}
