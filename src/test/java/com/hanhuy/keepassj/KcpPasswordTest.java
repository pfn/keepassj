package com.hanhuy.keepassj;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author pfnguyen
 */
public class KcpPasswordTest {
    final static int[] PASSWORD_12345 = {
            0x59,0x94,0x47,0x1a,0xbb,0x01,0x11,0x2a,
            0xfc,0xc1,0x81,0x59,0xf6,0xcc,0x74,0xb4,
            0xf5,0x11,0xb9,0x98,0x06,0xda,0x59,0xb3,
            0xca,0xf5,0xa9,0xc1,0x73,0xca,0xcf,0xc5
    };

    @Test
    public void password12345() {
        KcpPassword pw = new KcpPassword("12345");
        byte[] key = pw.getKeyData().ReadData();
        int[] asInt = new int[key.length];
        for (int i = 0; i < key.length; i++) {
            asInt[i] = key[i] & 0xff;
        }
        Assert.assertArrayEquals(PASSWORD_12345, asInt);
    }
}
