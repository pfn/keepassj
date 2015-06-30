package com.hanhuy.keepassj.database;

import com.hanhuy.keepassj.TimeUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * @author pfnguyen
 */
public class TimeUtilTest {
    @Test
    public void simplePad0s() {
        String s = TimeUtil.pad0s(1, 4);
        Assert.assertEquals("0001", s);
        s = TimeUtil.pad0s(11, 4);
        Assert.assertEquals("0011", s);
        s = TimeUtil.pad0s(111, 4);
        Assert.assertEquals("0111", s);
        s = TimeUtil.pad0s(1111, 4);
        Assert.assertEquals("1111", s);
    }

    @Test
    public void serializeDate() {
        Date d = new Date(1l);
        String s = TimeUtil.SerializeUtc(d);
        Assert.assertEquals("1970-01-01T00:00:00Z", s);
    }

    @Test
    public void deserializeDate() {
        Date[] res = new Date[1];
        boolean r = TimeUtil.TryDeserializeUtc("1970-01-01T00:00:00Z", res);
        Assert.assertTrue(r);
        Assert.assertTrue(res[0] != null);
        Assert.assertTrue(res[0].getTime() >= 0);
        Assert.assertTrue(res[0].getTime() < 1000);
        r = TimeUtil.TryDeserializeUtc("1970-09-09T09:09:09Z", res);
        Calendar c = Calendar.getInstance();
        c.setTimeZone(TimeUtil.UTC);
        c.setTime(res[0]);
        Assert.assertTrue(r);
        Assert.assertTrue(res[0] != null);
        Assert.assertEquals(9 - 1, c.get(Calendar.MONTH));
        Assert.assertEquals(9, c.get(Calendar.DAY_OF_MONTH));
        Assert.assertEquals(9, c.get(Calendar.HOUR_OF_DAY));
        Assert.assertEquals(9, c.get(Calendar.MINUTE));
        Assert.assertEquals(9, c.get(Calendar.SECOND));
        r = TimeUtil.TryDeserializeUtc("1970-11-11T19:19:19Z", res);
        c = Calendar.getInstance();
        c.setTimeZone(TimeUtil.UTC);
        c.setTime(res[0]);
        Assert.assertTrue(r);
        Assert.assertTrue(res[0] != null);
        Assert.assertEquals(11 - 1, c.get(Calendar.MONTH));
        Assert.assertEquals(11, c.get(Calendar.DAY_OF_MONTH));
        Assert.assertEquals(19, c.get(Calendar.HOUR_OF_DAY));
        Assert.assertEquals(19, c.get(Calendar.MINUTE));
        Assert.assertEquals(19, c.get(Calendar.SECOND));
    }
}
