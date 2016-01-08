package com.hanhuy.keepassj.spr;

import com.google.common.io.BaseEncoding;
import com.hanhuy.keepassj.*;

import java.util.ArrayList;
import java.util.List;

/**
 * @author pfnguyen
 */
public class EntryUtil {
    @Deprecated
    public static String FillPlaceholders(String strText, SprContext ctx)
    {
        return FillPlaceholders(strText, ctx, 0);
    }

    public static String FillPlaceholders(String strText, SprContext ctx,
                                          int uRecursionLevel) {
        if ((ctx == null) || (ctx.getEntry() == null)) return strText;

        String str = strText;

        if (ctx.getFlags().contains(SprCompileFlags.NewPassword))
            str = ReplaceNewPasswordPlaceholder(str, ctx, uRecursionLevel);

        if (ctx.getFlags().contains(SprCompileFlags.HmacOtp))
            str = ReplaceHmacOtpPlaceholder(str, ctx);

        return str;
    }
    private static String ReplaceNewPasswordPlaceholder(String strText,
                                                        SprContext ctx, int uRecursionLevel)
    {
        PwEntry pe = ctx.getEntry();
        PwDatabase pd = ctx.getDatabase();
        if((pe == null) || (pd == null)) return strText;

        String[] str = {strText};

        final String strNewPwStart = "{NEWPASSWORD";
        if(str[0].toLowerCase().indexOf(strNewPwStart.toLowerCase()) < 0) return str[0];

        String strGen = null;

        int[] iStart = new int[1];
        List<String> lParams = new ArrayList<String>();
        while(SprEngine.ParseAndRemovePlhWithParams(str, ctx, uRecursionLevel,
                strNewPwStart + ":", iStart, lParams, true))
        {
//            if(strGen == null)
//                strGen = GeneratePassword((((lParams != null) &&
//                        (lParams.size() > 0)) ? lParams.get(0) : ""), ctx);

            String strIns = SprEngine.TransformContent(strGen, ctx);
            str[0] = StrUtil.Insert(str[0], iStart[0], strIns);
        }

        final String strNewPwPlh = strNewPwStart + "}";
        if(str[0].toLowerCase().indexOf(strNewPwPlh.toLowerCase()) >= 0)
        {
//            if(strGen == null) strGen = GeneratePassword(null, ctx);

            String strIns = SprEngine.TransformContent(strGen, ctx);
            str[0] = StrUtil.ReplaceCaseInsensitive(str[0], strNewPwPlh, strIns);
        }

        if(strGen != null)
        {
            pe.CreateBackup(pd);

            ProtectedString psGen = new ProtectedString(false, strGen);
            pe.getStrings().Set(PwDefs.PasswordField, psGen);

            pe.Touch(true, false);
            pd.setModified(true);
        }
        else { assert false; }

        return str[0];
    }
    private static String ReplaceHmacOtpPlaceholder(String strText,
                                                    SprContext ctx)
    {
        PwEntry pe = ctx.getEntry();
        PwDatabase pd = ctx.getDatabase();
        if((pe == null) || (pd == null)) return strText;

        String str = strText;

        final String strHmacOtpPlh = "{HMACOTP}";
        if(str.toLowerCase().indexOf(strHmacOtpPlh.toLowerCase()) >= 0)
        {
            final String strKeyFieldUtf8 = "HmacOtp-Secret";
            final String strKeyFieldHex = "HmacOtp-Secret-Hex";
            final String strKeyFieldBase32 = "HmacOtp-Secret-Base32";
            final String strKeyFieldBase64 = "HmacOtp-Secret-Base64";
            final String strCounterField = "HmacOtp-Counter";

            byte[] pbSecret = null;
            try
            {
                String strKey = pe.getStrings().ReadSafe(strKeyFieldUtf8);
                if(strKey.length() > 0)
                    pbSecret = strKey.getBytes(StrUtil.Utf8);

                if(pbSecret == null)
                {
                    strKey = pe.getStrings().ReadSafe(strKeyFieldHex);
                    if(strKey.length() > 0)
                        pbSecret = MemUtil.HexStringToByteArray(strKey.toUpperCase());
                }

                if(pbSecret == null)
                {
                    strKey = pe.getStrings().ReadSafe(strKeyFieldBase32);
                    if(strKey.length() > 0)
                        pbSecret = MemUtil.ParseBase32(strKey.toUpperCase());
                }

                if(pbSecret == null)
                {
                    strKey = pe.getStrings().ReadSafe(strKeyFieldBase64);
                    if(strKey.length() > 0)
                        pbSecret = BaseEncoding.base64().decode(strKey.toUpperCase());
                }
            }
            catch(Exception e) { assert false; }
            if(pbSecret == null) pbSecret = new byte[0];

            String strCounter = pe.getStrings().ReadSafe(strCounterField);
            long uCounter = parseLong(strCounter);

            String strValue = HmacOtp.Generate(pbSecret, uCounter, 6,
                    false, -1);

            pe.getStrings().Set(strCounterField, new ProtectedString(false,
                    String.valueOf(uCounter + 1)));
            pd.setModified(true);

            str = StrUtil.ReplaceCaseInsensitive(str, strHmacOtpPlh, strValue);
        }

        return str;
    }

    public static long parseLong(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    public static int parseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
