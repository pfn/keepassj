package com.hanhuy.keepassj;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;

/**
 * @author pfnguyen
 */
public class KcpKeyFileTest {
    final static int[] KEYFILE_DATA = {
            0xcd,0xa4,0xd6,0xa6,0x15,0x4d,0xb5,0x16,
            0xec,0xa6,0x7c,0x24,0xaa,0x3c,0xbc,0x14,
            0x64,0xf2,0xe4,0x8a,0x82,0x53,0x1f,0x7e,
            0x14,0xd6,0xf9,0x1f,0xe5,0x5d,0x07,0x6e
    };
    @Test
    public void keyfileData() throws Exception {
        KcpKeyFile keyfile = new KcpKeyFile(new File(KcpKeyFileTest.class.getClassLoader().getResource("keyfile.key").toURI()).getAbsolutePath());
        byte[] key = keyfile.getKeyData().ReadData();
        int[] asInt = new int[key.length];
        for (int i = 0; i < key.length; i++) {
            asInt[i] = key[i] & 0xff;
        }
        Assert.assertArrayEquals(KEYFILE_DATA, asInt);
    }
}
