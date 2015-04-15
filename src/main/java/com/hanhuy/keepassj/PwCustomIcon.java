package com.hanhuy.keepassj;
/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2014 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

import java.util.HashMap;

/// <summary>
/// Custom icon. <c>PwCustomIcon</c> objects are immutable.
/// </summary>
public class PwCustomIcon
{
    private PwUuid m_pwUuid;
    private byte[] m_pbImageDataPng;

    // Recommended maximum sizes, not obligatory
    private final static int MaxWidth = 128;
    private final static int MaxHeight = 128;

    public PwUuid getUuid()
    {
        return m_pwUuid;
    }

    public byte[] getImageDataPng()
    {
        return m_pbImageDataPng;
    }


    public PwCustomIcon(PwUuid pwUuid, byte[] pbImageDataPng)
    {
        if(pwUuid == null) throw new IllegalArgumentException("pwUuid");
        if(pwUuid.Equals(PwUuid.Zero)) throw new IllegalArgumentException("pwUuid == 0");

        if(pbImageDataPng == null) throw new IllegalArgumentException("pbImageDataPng");

        m_pwUuid = pwUuid;
        m_pbImageDataPng = pbImageDataPng;

    }
    /// <summary>
    /// Get the icon as an <c>Image</c> (original size).
    /// </summary>
}
