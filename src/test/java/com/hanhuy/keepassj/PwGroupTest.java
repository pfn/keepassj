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

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.hanhuy.keepassj.database.TestData;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class PwGroupTest {

    static PwGroup mPG;

    @BeforeClass
    public static void setUp() throws Exception {

        mPG = TestData.GetTest1().getRootGroup().GetGroups(false).GetAt(0);

    }

    @Test
    public void testGroupName() {
        PwObjectList<PwGroup> groups = mPG.GetGroups(true);
        Assert.assertTrue("Name was " + mPG.getName(), mPG.getName().equals("General"));
    }

    final static Function<PwGroup,String> groupToName = new Function<PwGroup,String>() {
        @Override
        public String apply(PwGroup input) {
            return input.getName();
        }
    };
}

