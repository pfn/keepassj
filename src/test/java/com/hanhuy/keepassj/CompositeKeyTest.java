package com.hanhuy.keepassj;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;

/**
 * @author pfnguyen
 */
public class CompositeKeyTest {
    final static int[] KEY_DATA_12345 = {
            0xe2, 0x66, 0xcf, 0x46, 0x7f, 0x14, 0xe2, 0x3d,
            0x9d, 0x33, 0x82, 0xcd, 0x1d, 0x41, 0x03, 0xda,
            0x2a, 0x81, 0xd7, 0xdc, 0xdc, 0x35, 0x23, 0xb8,
            0xea, 0xcc, 0x50, 0x3a, 0x20, 0x1b, 0x1a, 0x68
    };

    final static int[] COMPOSITE_KEY_DATA = {
            0x3b,0x34,0x9e,0x1a,0x86,0xd7,0x50,0xdb,0xdb,0x6b,0x7e,0x23,0x82,0x98,0x9a,0x21,0xa7,0x82,0x68,0x4b,0xcf,0x3c,0x74,0x68,0xf1,0x4b,0x75,0x61,0xa7,0x63,0x91,0xfc
    };
    @Test
    public void keydata12345() {
        KcpPassword pw = new KcpPassword("12345");
        byte[] pwdata = pw.getKeyData().ReadData();
        CompositeKey key = new CompositeKey();
        key.AddUserKey(pw);
        byte[] keydata = key.GenerateKey32(pwdata, 6000).ReadData();
        int[] asInt = new int[keydata.length];
        for (int i = 0; i < keydata.length; i++) {
            asInt[i] = keydata[i] & 0xff;
        }
        Assert.assertArrayEquals(KEY_DATA_12345, asInt);
    }
    @Test
    public void compositeKeyData() throws Exception {
        KcpPassword pw = new KcpPassword("12345");
        KcpKeyFile keyfile = new KcpKeyFile(new File(KcpKeyFileTest.class.getClassLoader().getResource("keyfile.key").toURI()).getAbsolutePath());
        CompositeKey key = new CompositeKey();
        key.AddUserKey(pw);
        key.AddUserKey(keyfile);
        byte[] keydata = key.GenerateKey32(keyfile.getKeyData().ReadData(), 6000).ReadData();
        int[] asInt = new int[keydata.length];
        for (int i = 0; i < keydata.length; i++) {
            asInt[i] = keydata[i] & 0xff;
        }
        Assert.assertArrayEquals(COMPOSITE_KEY_DATA, asInt);
    }
}
