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

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/// <summary>
/// Generate HMAC-based one-time passwords as specified in RFC 4226.
/// </summary>
public class HmacOtp
{
    private static final int[] vDigitsPower = new int[]{ 1, 10, 100,
        1000, 10000, 100000, 1000000, 10000000, 100000000 };

    public static String Generate(byte[] pbSecret, long uFactor,
                                  int uCodeDigits, boolean bAddChecksum, int iTruncationOffset)
    {
        byte[] pbText = MemUtil.UInt64ToBytes(uFactor);
        StrUtil.ArraysReverse(pbText); // Big-Endian

        HMac hsha1 = new HMac(new SHA1Digest());
        KeyParameter key = new KeyParameter(pbSecret);
        hsha1.init(key);
        byte[] pbHash = new byte[hsha1.getMacSize()];
        hsha1.update(pbText, 0, pbText.length);
        hsha1.doFinal(pbHash, 0);

        int uOffset = (int)(pbHash[pbHash.length - 1] & 0xF);
        if((iTruncationOffset >= 0) && (iTruncationOffset < (pbHash.length - 4)))
            uOffset = (int)iTruncationOffset;

        int uBinary = (int)(((pbHash[uOffset] & 0x7F) << 24) |
                ((pbHash[uOffset + 1] & 0xFF) << 16) |
                ((pbHash[uOffset + 2] & 0xFF) << 8) |
                (pbHash[uOffset + 3] & 0xFF));

        int uOtp = (uBinary % vDigitsPower[uCodeDigits]);
        if(bAddChecksum)
            uOtp = ((uOtp * 10) + CalculateChecksum(uOtp, uCodeDigits));

        int uDigits = (bAddChecksum ? (uCodeDigits + 1) : uCodeDigits);
        return String.format("%0" + uDigits + "d", uOtp);
    }

    private static final int[] vDoubleDigits = new int[]{ 0, 2, 4, 6, 8,
        1, 3, 5, 7, 9 };

    private static int CalculateChecksum(int uNum, int uDigits)
    {
        boolean bDoubleDigit = true;
        int uTotal = 0;

        while(0 < uDigits--)
        {
            int uDigit = (uNum % 10);
            uNum /= 10;

            if(bDoubleDigit) uDigit = vDoubleDigits[uDigit];

            uTotal += uDigit;
            bDoubleDigit = !bDoubleDigit;
        }

        int uResult = (uTotal % 10);
        if(uResult != 0) uResult = 10 - uResult;

        return uResult;
    }
}
