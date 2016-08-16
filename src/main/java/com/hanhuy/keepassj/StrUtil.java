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

        import com.google.common.base.Charsets;
        import com.google.common.base.Joiner;
        import com.google.common.base.Strings;
        import com.google.common.base.Predicate;
        import com.google.common.collect.Iterables;
        import com.google.common.collect.Lists;
        import com.google.common.io.BaseEncoding;

        import java.io.ByteArrayOutputStream;
        import java.nio.charset.Charset;
        import java.text.SimpleDateFormat;
        import java.util.*;
        import java.util.regex.Pattern;

/// <summary>
/// Character stream class.
/// </summary>
enum SeekOrigin {
    Begin,
    Current,
    End
}
class CharStream
{
    private String m_strString = "";
    private int m_nPos = 0;

    public CharStream(String str)
    {
        assert str != null;
        if(str == null) throw new IllegalArgumentException("str");

        m_strString = str;
    }

    public void Seek(SeekOrigin org, int nSeek)
    {
        if(org == SeekOrigin.Begin)
            m_nPos = nSeek;
        else if(org == SeekOrigin.Current)
            m_nPos += nSeek;
        else if(org == SeekOrigin.End)
            m_nPos = m_strString.length() + nSeek;
    }

    public char ReadChar()
    {
        if(m_nPos < 0) return Character.MIN_VALUE;
        if(m_nPos >= m_strString.length()) return Character.MIN_VALUE;

        char chRet = m_strString.charAt(m_nPos);
        ++m_nPos;
        return chRet;
    }

    public char ReadChar(boolean bSkipWhiteSpace)
    {
        if(!bSkipWhiteSpace) return ReadChar();

        while(true)
        {
            char ch = ReadChar();

            if((ch != ' ') && (ch != '\t') && (ch != '\r') && (ch != '\n'))
                return ch;
        }
    }

    public char PeekChar()
    {
        if(m_nPos < 0) return Character.MIN_VALUE;
        if(m_nPos >= m_strString.length()) return Character.MIN_VALUE;

        return m_strString.charAt(m_nPos);
    }

    public char PeekChar(boolean bSkipWhiteSpace)
    {
        if(!bSkipWhiteSpace) return PeekChar();

        int iIndex = m_nPos;
        while(true)
        {
            if(iIndex < 0) return Character.MIN_VALUE;
            if(iIndex >= m_strString.length()) return Character.MIN_VALUE;

            char ch = m_strString.charAt(iIndex);

            if((ch != ' ') && (ch != '\t') && (ch != '\r') && (ch != '\n'))
                return ch;

            ++iIndex;
        }
    }
}

enum StrEncodingType
{
    Unknown,
    Default,
    Ascii,
    Utf7,
    Utf8,
    Utf16LE,
    Utf16BE,
    Utf32LE,
    Utf32BE
}

class StrEncodingInfo
{
    private final StrEncodingType m_type;
    public StrEncodingType getType()
    {
        return m_type;
    }

    private final String m_strName;
    public String getName()
    {
        return m_strName;
    }

    private final Charset m_enc;
    public Charset getEncoding()
    {
        return m_enc;
    }

    private final int m_cbCodePoint;
    /// <summary>
    /// Size of a character in bytes.
    /// </summary>
    public int getCodePointSize()
    {
        return m_cbCodePoint;
    }

    private final byte[] m_vSig;
    /// <summary>
    /// Start signature of the text (byte order mark).
    /// May be <c>null</c> or empty, if no signature is known.
    /// </summary>
    public byte[] getStartSignature()
    {
        return m_vSig;
    }

    public StrEncodingInfo(StrEncodingType t, String strName, Charset enc,
                           int cbCodePoint, byte[] vStartSig)
    {
        if(strName == null) throw new IllegalArgumentException("strName");
        if(enc == null) throw new IllegalArgumentException("enc");
        if(cbCodePoint <= 0) throw new ArrayIndexOutOfBoundsException("cbCodePoint");

        m_type = t;
        m_strName = strName;
        m_enc = enc;
        m_cbCodePoint = cbCodePoint;
        m_vSig = vStartSig;
    }
}

/// <summary>
/// A class containing various String helper methods.
/// </summary>
public class StrUtil {
    public final static StringComparison CaseIgnoreCmp = StringComparison.OrdinalIgnoreCase;

    private static boolean m_bRtl = false;

    public static boolean isRightToLeft() {
        return m_bRtl;
    }

    public void setRightToLeft(boolean value) {
        m_bRtl = value;
    }

    private static Charset m_encUtf8 = null;
    public static Charset Utf8 = Charsets.UTF_8;

    private static List<StrEncodingInfo> m_lEncs = null;

    public static Iterable<StrEncodingInfo> getEncodings() {
        if (m_lEncs != null) return m_lEncs;

        List<StrEncodingInfo> l = new ArrayList<StrEncodingInfo>();

        l.add(new StrEncodingInfo(StrEncodingType.Ascii,
                "ASCII", Charsets.US_ASCII, 1, null));
        l.add(new StrEncodingInfo(StrEncodingType.Utf8,
                "Unicode (UTF-8)", StrUtil.Utf8, 1, new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF}));
        l.add(new StrEncodingInfo(StrEncodingType.Utf16LE,
                "Unicode (UTF-16 LE)", Charsets.UTF_16LE,
                2, new byte[]{(byte) 0xFF, (byte) 0xFE}));
        l.add(new StrEncodingInfo(StrEncodingType.Utf16BE,
                "Unicode (UTF-16 BE)", Charsets.UTF_16BE,
                2, new byte[]{(byte) 0xFE, (byte) 0xFF}));
            /*
				l.add(new StrEncodingInfo(StrEncodingType.Utf32LE,
                        "Unicode (UTF-32 LE)", new UTF32Encoding(false, false),
                        4, new byte[]{0xFF, 0xFE, 0x0, 0x0}));
				l.add(new StrEncodingInfo(StrEncodingType.Utf32BE,
                        "Unicode (UTF-32 BE)", new UTF32Encoding(true, false),
                        4, new byte[]{0x0, 0x0, 0xFE, 0xFF}));
                        */

        m_lEncs = l;
        return l;
    }

    // public static String RtfPar
    // {
    //	// get { return (m_bRtl ? "\\rtlpar " : "\\par "); }
    //	get { return "\\par "; }
    // }

    // /// <summary>
    // /// Convert a String into a valid RTF String.
    // /// </summary>
    // /// <param name="str">Any String.</param>
    // /// <returns>RTF-encoded String.</returns>
    // public static String MakeRtfString(String str)
    // {
    //	assert str != null; if(str == null) throw new IllegalArgumentException("str");
    //	str = str.Replace("\\", "\\\\");
    //	str = str.Replace("\r", String.Empty);
    //	str = str.Replace("{", "\\{");
    //	str = str.Replace("}", "\\}");
    //	str = str.Replace("\n", StrUtil.RtfPar);
    //	StringBuilder sbEncoded = new StringBuilder();
    //	for(int i = 0; i < str.Length; ++i)
    //	{
    //		char ch = str[i];
    //		if((int)ch >= 256)
    //			sbEncoded.Append(StrUtil.RtfEncodeChar(ch));
    //		else sbEncoded.Append(ch);
    //	}
    //	return sbEncoded.ToString();
    // }

    public static String RtfEncodeChar(char ch) {
        // Unicode character values must be encoded using
        // 16-bit numbers (decimal); Unicode values greater
        // than 32767 must be expressed as negative numbers
        short sh = (short) ch;
        return ("\\u" + sh + "?");
    }

    /// <summary>
    /// Convert a String into a valid HTML sequence representing that String.
    /// </summary>
    /// <param name="str">String to convert.</param>
    /// <returns>String, HTML-encoded.</returns>
    public static String StringToHtml(String str) {
        assert str != null;
        if (str == null) throw new IllegalArgumentException("str");

        str = str.replace("&", "&amp;");
        str = str.replace("<", "&lt;");
        str = str.replace(">", "&gt;");
        str = str.replace("\"", "&quot;");
        str = str.replace("\'", "&#39;");

        str = NormalizeNewLines(str, false);
        str = str.replace("\n", "<br />\n");

        return str;
    }

    public static String XmlToString(String str) {
        assert str != null;
        if (str == null) throw new IllegalArgumentException("str");

        str = str.replace("&amp;", "&");
        str = str.replace("&lt;", "<");
        str = str.replace("&gt;", ">");
        str = str.replace("&quot;", "\"");
        str = str.replace("&#39;", "\'");

        return str;
    }

    public static String ReplaceCaseInsensitive(String strString, String strFind,
                                                String strNew) {
        assert strString != null;
        if (strString == null) return strString;
        assert strFind != null;
        if (strFind == null) return strString;
        assert strNew != null;
        if (strNew == null) return strString;

        String str = strString;

        int nPos = 0;
        while (nPos < str.length()) {
            nPos = str.toLowerCase().indexOf(strFind.toLowerCase(), nPos);
            if (nPos < 0) break;

//            str = str.Remove(nPos, strFind.length());
//            str = str.Insert(nPos, strNew);
            // TODO TEST ME!
            str = str.substring(0, nPos) + strNew + str.substring(nPos + strFind.length());

            nPos += strNew.length();
        }

        return str;
    }

    public static String Insert(String base, int offset, String insert) {
        return base.substring(0, offset) + insert + base.substring(offset);
    }
    public static String Remove(String src, int offset, int length) {
        return src.substring(0, offset) + src.substring(offset + length);
    }

    // /// <summary>
    // /// Initialize an RTF document based on given font face and size.
    // /// </summary>
    // /// <param name="sb"><c>StringBuilder</c> to put the generated RTF into.</param>
    // /// <param name="strFontFace">Face name of the font to use.</param>
    // /// <param name="fFontSize">Size of the font to use.</param>
    // public static void InitRtf(StringBuilder sb, String strFontFace, float fFontSize)
    // {
    //	assert sb != null; if(sb == null) throw new IllegalArgumentException("sb");
    //	assert strFontFace != null; if(strFontFace == null) throw new IllegalArgumentException("strFontFace");
    //	sb.Append("{\\rtf1");
    //	if(m_bRtl) sb.Append("\\fbidis");
    //	sb.Append("\\ansi\\ansicpg");
    //	sb.Append(Encoding.Default.CodePage);
    //	sb.Append("\\deff0{\\fonttbl{\\f0\\fswiss MS Sans Serif;}{\\f1\\froman\\fcharset2 Symbol;}{\\f2\\fswiss ");
    //	sb.Append(strFontFace);
    //	sb.Append(";}{\\f3\\fswiss Arial;}}");
    //	sb.Append("{\\colortbl\\red0\\green0\\blue0;}");
    //	if(m_bRtl) sb.Append("\\rtldoc");
    //	sb.Append("\\deflang1031\\pard\\plain\\f2\\cf0 ");
    //	sb.Append("\\fs");
    //	sb.Append((int)(fFontSize * 2));
    //	if(m_bRtl) sb.Append("\\rtlpar\\qr\\rtlch ");
    // }

    // /// <summary>
    // /// Convert a simple HTML String to an RTF String.
    // /// </summary>
    // /// <param name="strHtmlString">Input HTML String.</param>
    // /// <returns>RTF String representing the HTML input String.</returns>
    // public static String SimpleHtmlToRtf(String strHtmlString)
    // {
    //	StringBuilder sb = new StringBuilder();
    //	StrUtil.InitRtf(sb, "Microsoft Sans Serif", 8.25f);
    //	sb.Append(" ");
    //	String str = MakeRtfString(strHtmlString);
    //	str = str.Replace("<b>", "\\b ");
    //	str = str.Replace("</b>", "\\b0 ");
    //	str = str.Replace("<i>", "\\i ");
    //	str = str.Replace("</i>", "\\i0 ");
    //	str = str.Replace("<u>", "\\ul ");
    //	str = str.Replace("</u>", "\\ul0 ");
    //	str = str.Replace("<br />", StrUtil.RtfPar);
    //	sb.Append(str);
    //	return sb.ToString();
    // }

    /// <summary>
    /// Convert a <c>Color</c> to a HTML color identifier String.
    /// </summary>
    /// <param name="color">Color to convert.</param>
    /// <param name="bEmptyIfTransparent">If this is <c>true</c>, an empty String
    /// is returned if the color is transparent.</param>
    /// <returns>HTML color identifier String.</returns>
    public static String ColorToUnnamedHtml(Color color, boolean bEmptyIfTransparent) {
        if (bEmptyIfTransparent && (color.A != 255))
            return "";

        StringBuilder sb = new StringBuilder();
        byte bt;

        sb.append('#');

        bt = (byte) (color.R >> 4);
        if (bt < 10) sb.append((char) ('0' + bt));
        else sb.append((char) ('A' - 10 + bt));
        bt = (byte) (color.R & 0x0F);
        if (bt < 10) sb.append((char) ('0' + bt));
        else sb.append((char) ('A' - 10 + bt));

        bt = (byte) (color.G >> 4);
        if (bt < 10) sb.append((char) ('0' + bt));
        else sb.append((char) ('A' - 10 + bt));
        bt = (byte) (color.G & 0x0F);
        if (bt < 10) sb.append((char) ('0' + bt));
        else sb.append((char) ('A' - 10 + bt));

        bt = (byte) (color.B >> 4);
        if (bt < 10) sb.append((char) ('0' + bt));
        else sb.append((char) ('A' - 10 + bt));
        bt = (byte) (color.B & 0x0F);
        if (bt < 10) sb.append((char) ('0' + bt));
        else sb.append((char) ('A' - 10 + bt));

        return sb.toString();
    }

    public static boolean TryParseInt(String str, int[] n) {
        try {
            n[0] = Integer.parseInt(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean TryParseIntInvariant(String str, int[] n) {
        return TryParseInt(str, n);
    }

    public static boolean TryParseUInt(String str, int[] u) {
        return TryParseInt(str, u);
    }

    public static boolean TryParseUIntInvariant(String str, int[] u) {
        return TryParseInt(str, u);
    }

    public static boolean TryParseLong(String str, long[] n) {
        try {
            n[0] = Long.parseLong(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean TryParseShort(String str, short[] n) {
        try {
            n[0] = Short.parseShort(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean TryParseUShort(String str, short[] u) {
        return TryParseShort(str, u);
    }

    public static boolean TryParseLongInvariant(String str, long[] n) {
        return TryParseLong(str, n);
    }

    public static boolean TryParseULong(String str, long[] u) {
        return TryParseLong(str, u);
    }

    public static boolean TryParseULongInvariant(String str, long[] u) {
        return TryParseLong(str, u);
    }

    public static boolean TryParseDateTime(String str, Date[] dt) {
        SimpleDateFormat sdf = new SimpleDateFormat();
        try {
            dt[0] = sdf.parse(str);
            return true;
        } catch (Exception e) {
            dt[0] = new Date(0);
            return false;
        }
    }

    public static String CompactString3Dots(String strText, int nMaxChars) {
        assert strText != null;
        if (strText == null) throw new IllegalArgumentException("strText");
        assert nMaxChars >= 0;
        if (nMaxChars < 0)
            throw new ArrayIndexOutOfBoundsException("nMaxChars");

        if (nMaxChars == 0) return "";
        if (strText.length() <= nMaxChars) return strText;

        if (nMaxChars <= 3) return strText.substring(0, nMaxChars);

        return strText.substring(0, nMaxChars - 3) + "...";
    }

    public static String GetStringBetween(String strText, int nStartIndex,
                                          String strStart, String strEnd) {
        int[] nTemp = new int[1];
        return GetStringBetween(strText, nStartIndex, strStart, strEnd, nTemp);
    }

    public static String GetStringBetween(String strText, int nStartIndex,
                                          String strStart, String strEnd, int[] nInnerStartIndex) {
        if (strText == null) throw new IllegalArgumentException("strText");
        if (strStart == null) throw new IllegalArgumentException("strStart");
        if (strEnd == null) throw new IllegalArgumentException("strEnd");

        nInnerStartIndex[0] = -1;

        int nIndex = strText.indexOf(strStart, nStartIndex);
        if (nIndex < 0) return "";

        nIndex += strStart.length();

        int nEndIndex = strText.indexOf(strEnd, nIndex);
        if (nEndIndex < 0) return "";

        nInnerStartIndex[0] = nIndex;
        return strText.substring(nIndex, nEndIndex - nIndex);
    }

    /// <summary>
    /// Removes all characters that are not valid XML characters,
    /// according to http://www.w3.org/TR/xml/#charsets .
    /// </summary>
    /// <param name="strText">Source text.</param>
    /// <returns>Text containing only valid XML characters.</returns>
    public static String SafeXmlString(String strText) {
        assert strText != null; // No throw
        if (Strings.isNullOrEmpty(strText)) return strText;

        int nLength = strText.length();
        StringBuilder sb = new StringBuilder(nLength);

        for (int i = 0; i < nLength; ++i) {
            char ch = strText.charAt(i);

            if (((ch >= '\u0020') && (ch <= '\uD7FF')) ||
                    (ch == '\u0009') || (ch == '\n') || (ch == '\r') ||
                    ((ch >= '\uE000') && (ch <= '\uFFFD')))
                sb.append(ch);
            else if ((ch >= '\uD800') && (ch <= '\uDBFF')) // High surrogate
            {
                if ((i + 1) < nLength) {
                    char chLow = strText.charAt(i + 1);
                    if ((chLow >= '\uDC00') && (chLow <= '\uDFFF')) // Low sur.
                    {
                        sb.append(ch);
                        sb.append(chLow);
                        ++i;
                    } else {
                        assert false;
                    } // Low sur. invalid
                } else {
                    assert false;
                } // Low sur. missing
            }

            assert (ch < '\uDC00') || (ch > '\uDFFF'); // Lonely low sur.
        }

        return sb.toString();
    }

    /*private static Pattern g_rxNaturalSplit = null;
    public static int CompareNaturally(String strX, String strY) {
        assert strX != null;
        if (strX == null) throw new IllegalArgumentException("strX");
        assert strY != null;
        if (strY == null) throw new IllegalArgumentException("strY");

        if (g_rxNaturalSplit == null)
            g_rxNaturalSplit = Pattern.compile("([0-9]+)");

        String[] vPartsX = g_rxNaturalSplit.split(strX);
        String[] vPartsY = g_rxNaturalSplit.split(strY);

		int n = Math.min(vPartsX.length, vPartsY.length);
		for(int i = 0; i < n; ++i)
        {
            String strPartX = vPartsX[i], strPartY = vPartsY[i];
            int iPartCompare;

            try {
                long uX = Long.parseLong(strPartX);
                long uY = Long.parseLong(strPartY);
                iPartCompare = uX < uY ? -1 : uX > uY ? 1 : 0;
            }
			catch(Exception) { iPartCompare = string.Compare(strPartX, strPartY, true); }

            if (iPartCompare != 0) return iPartCompare;
        }

        if (vPartsX.length == vPartsY.length) return 0;
        if (vPartsX.length < vPartsY.length) return -1;
        return 1;
    } */
		public static int CompareNaturally(String strX, String strY)
		{
			assert(strX != null);
			if(strX == null) throw new IllegalArgumentException("strX");
			assert(strY != null);
			if(strY == null) throw new IllegalArgumentException("strY");

			int cX = strX.length();
			int cY = strY.length();
			if(cX == 0) return ((cY == 0) ? 0 : -1);
			if(cY == 0) return 1;

			char chFirstX = strX.charAt(0);
			char chFirstY = strY.charAt(0);
			boolean bExpNum = ((chFirstX >= '0') && (chFirstX <= '9'));
			boolean bExpNumY = ((chFirstY >= '0') && (chFirstY <= '9'));
			if(bExpNum != bExpNumY) return strX.toLowerCase().compareTo(strY.toLowerCase());

			int pX = 0;
			int pY = 0;
			while((pX < cX) && (pY < cY))
			{
				assert(((strX.charAt(pX) >= '0') && (strX.charAt(pX) <= '9')) == bExpNum);
				assert(((strY.charAt(pY) >= '0') && (strY.charAt(pY) <= '9')) == bExpNum);

				int pExclX = pX + 1;
				while(pExclX < cX)
				{
					char ch = strX.charAt(pExclX);
					boolean bChNum = ((ch >= '0') && (ch <= '9'));
					if(bChNum != bExpNum) break;
					++pExclX;
				}

				int pExclY = pY + 1;
				while(pExclY < cY)
				{
					char ch = strY.charAt(pExclY);
					boolean bChNum = ((ch >= '0') && (ch <= '9'));
					if(bChNum != bExpNum) break;
					++pExclY;
				}

				String strPartX = strX.substring(pX, pExclX - pX);
				String strPartY = strY.substring(pY, pExclY - pY);

				boolean bStrCmp = true;
				if(bExpNum)
				{
					// 2^64 - 1 = 18446744073709551615 has length 20
					if((strPartX.length() <= 19) && (strPartY.length() <= 19))
					{
						long uX, uY;
                        try {
                            uX = Long.parseLong(strPartX);
                            uY = Long.parseLong(strPartY);
                            if (uX < uY) return -1;
                            if (uX > uY) return 1;

                            bStrCmp = false;
                        } catch (NumberFormatException e) {
                                assert(false);
                        }
					}
					else
					{
						double dX, dY;
                        try {
                            dX = Double.parseDouble(strPartX);
                            dY = Double.parseDouble(strPartY);
                            if(dX < dY) return -1;
                            if(dX > dY) return 1;

                            bStrCmp = false;
                        }
                        catch (NumberFormatException e) {
						    assert(false);
                        }
					}
				}
				if(bStrCmp)
				{
					int c = strPartX.toLowerCase().compareTo(strPartY.toLowerCase());
					if(c != 0) return c;
				}

				bExpNum = !bExpNum;
				pX = pExclX;
				pY = pExclY;
			}

			if(pX >= cX)
			{
				assert(pX == cX);
				if(pY >= cY) { assert(pY == cY); return 0; }
				return -1;
			}

			assert(pY == cY);
			return 1;
    }

    public static String RemoveAccelerator(String strMenuText) {
        if (strMenuText == null)
            throw new IllegalArgumentException("strMenuText");

        String str = strMenuText;

        for (char ch = 'A'; ch <= 'Z'; ++ch) {
            String strEnhAcc = "(&" + ch + ")";
            if (str.indexOf(strEnhAcc) >= 0) {
                str = str.replace(" " + strEnhAcc, "");
                str = str.replace(strEnhAcc, "");
            }
        }

        str = str.replace("&", "");

        return str;
    }

    public static String AddAccelerator(String strMenuText,
                                        List<Character> lAvailKeys) {
        if (strMenuText == null) {
            assert false;
            return null;
        }
        if (lAvailKeys == null) {
            assert false;
            return strMenuText;
        }

        int xa = -1, xs = 0;
        for (int i = 0; i < strMenuText.length(); ++i) {
            char ch = strMenuText.charAt(i);

            char chUpper = Character.toUpperCase(ch);
            xa = lAvailKeys.indexOf(chUpper);
            if (xa >= 0) {
                xs = i;
                break;
            }

            char chLower = Character.toLowerCase(ch);
            xa = lAvailKeys.indexOf(chLower);
            if (xa >= 0) {
                xs = i;
                break;
            }
        }

        if (xa < 0) return strMenuText;

        lAvailKeys.remove(xa);
//        return strMenuText.Insert(xs, "&");
        return strMenuText;
    }

    public static boolean IsHexString(String str, boolean bStrict) {
        if (str == null) throw new IllegalArgumentException("str");
        if (str.length() == 0) return true;

        for (char ch : str.toCharArray()) {
            if ((ch >= '0') && (ch <= '9')) continue;
            if ((ch >= 'a') && (ch <= 'z')) continue;
            if ((ch >= 'A') && (ch <= 'Z')) continue;

            if (bStrict) return false;

            if ((ch == ' ') || (ch == '\t') || (ch == '\r') || (ch == '\n'))
                continue;

            return false;
        }

        return true;
    }

    private static final Character[] m_vPatternPartsSep = new Character[]{'*'};

    public static boolean SimplePatternMatch(String strPattern, String strText,
                                             StringComparison sc) {
        if (strPattern == null)
            throw new IllegalArgumentException("strPattern");
        if (strText == null) throw new IllegalArgumentException("strText");

        if (strPattern.indexOf('*') < 0) return strText.equals(strPattern);

        String[] vPatternParts = Lists.newArrayList(Iterables.filter(
                Lists.newArrayList(strPattern.split("[" + Joiner.on("").join(m_vPatternPartsSep) + "]")),
                new Predicate<String>() {
            @Override
            public boolean apply(String s) {
                return !Strings.isNullOrEmpty(s);
            }
        })).toArray(new String[0]);
        if (vPatternParts == null) {
            assert false;
            return true;
        }
        if (vPatternParts.length == 0) return true;

        if (strText.length() == 0) return false;

        if (!strPattern.startsWith("*") && !strText.startsWith(vPatternParts[0])) {
            return false;
        }

        if (!strPattern.endsWith("*") && !strText.endsWith(vPatternParts[
                vPatternParts.length - 1])) {
            return false;
        }

        int iOffset = 0;
        for (int i = 0; i < vPatternParts.length; ++i) {
            String strPart = vPatternParts[i];

            int iFound = strText.indexOf(strPart, iOffset);
            if (iFound < iOffset) return false;

            iOffset = iFound + strPart.length();
            if (iOffset == strText.length())
                return (i == (vPatternParts.length - 1));
        }

        return true;
    }

    public static boolean StringToBool(String str) {
        if (Strings.isNullOrEmpty(str)) return false; // No assert

        String s = str.trim().toLowerCase();
        if ("true".equals(s)) return true;
        if ("yes".equals(s)) return true;
        if ("1".equals(s)) return true;
        if ("enabled".equals(s)) return true;
        if ("checked".equals(s)) return true;

        return false;
    }

    public static Boolean StringToBoolEx(String str) {
        if (Strings.isNullOrEmpty(str)) return null;

        String s = str.trim().toLowerCase();
        if ("true".equals(s)) return true;
        if ("false".equals(s)) return false;
        return null;
    }

    public static String BoolToString(boolean bValue) {
        return (bValue ? "true" : "false");
    }

    public static String BoolToStringEx(Boolean bValue) {
        if (bValue == null) return "null";
        return BoolToString(bValue);
    }

    /// <summary>
    /// Normalize new line characters in a String. Input strings may
    /// contain mixed new line character sequences from all commonly
    /// used operating systems (i.e. \r\n from Windows, \n from Unix
    /// and \r from Mac OS.
    /// </summary>
    /// <param name="str">String with mixed new line characters.</param>
    /// <param name="bWindows">If <c>true</c>, new line characters
    /// are normalized for Windows (\r\n); if <c>false</c>, new line
    /// characters are normalized for Unix (\n).</param>
    /// <returns>String with normalized new line characters.</returns>
    public static String NormalizeNewLines(String str, boolean bWindows) {
        if (Strings.isNullOrEmpty(str)) return str;

        str = str.replace("\r\n", "\n");
        str = str.replace("\r", "\n");

        if (bWindows) str = str.replace("\n", "\r\n");

        return str;
    }

    private static char[] m_vNewLineChars = null;

    public static int LastIndexOfAny(String str, char[] search) {
        int i = -1;
        for (char s: search) {
            i = Math.max(str.indexOf(s), i);
        }
        return i;
    }
    public static int IndexOfAny(String str, char[] search) {
        int i = -1;
        for (char s: search) {
            i = Math.min(str.indexOf(s), i);
        }
        return i;
    }
    public static int IndexOfAny(String str, String[] search) {
        int i = -1;
        for (String s: search) {
            i = Math.min(str.indexOf(s), i);
        }
        return i;
    }
    public static void NormalizeNewLines(ProtectedStringDictionary dict,
                                         boolean bWindows) {
        if (dict == null) {
            assert false;
            return;
        }

        if (m_vNewLineChars == null)
            m_vNewLineChars = new char[]{'\r', '\n'};

        List<String> vKeys = dict.GetKeys();
        for (String strKey : vKeys) {
            ProtectedString ps = dict.Get(strKey);
            if (ps == null) {
                assert false;
                continue;
            }

            String strValue = ps.ReadString();
            if (IndexOfAny(strValue, m_vNewLineChars) < 0) continue;

            dict.Set(strKey, new ProtectedString(ps.isProtected(),
                    NormalizeNewLines(strValue, bWindows)));
        }
    }

    public static String GetNewLineSeq(String str) {
        if (str == null) {
            assert false;
            return "\n";
        }

        int n = str.length(), nLf = 0, nCr = 0, nCrLf = 0;
        char chLast = Character.MIN_VALUE;
        for (int i = 0; i < n; ++i) {
            char ch = str.charAt(i);

            if (ch == '\r') ++nCr;
            else if (ch == '\n') {
                ++nLf;
                if (chLast == '\r') ++nCrLf;
            }

            chLast = ch;
        }

        nCr -= nCrLf;
        nLf -= nCrLf;

        int nMax = Math.max(nCrLf, Math.max(nCr, nLf));
        if (nMax == 0) return "\n";

        if (nCrLf == nMax) return "\r\n";
        return ((nLf == nMax) ? "\n" : "\r");
    }

    public static String AlphaNumericOnly(String str) {
        if (Strings.isNullOrEmpty(str)) return str;

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); ++i) {
            char ch = str.charAt(i);
            if (((ch >= 'a') && (ch <= 'z')) || ((ch >= 'A') && (ch <= 'Z')) ||
                    ((ch >= '0') && (ch <= '9')))
                sb.append(ch);
        }

        return sb.toString();
    }

    public static String FormatDataSize(long uBytes) {
        final long uKB = 1024;
        final long uMB = uKB * uKB;
        final long uGB = uMB * uKB;
        final long uTB = uGB * uKB;

        if (uBytes == 0) return "0 KB";
        if (uBytes <= uKB) return "1 KB";
        if (uBytes <= uMB) return (((uBytes - 1L) / uKB) + 1L) + " KB";
        if (uBytes <= uGB) return (((uBytes - 1L) / uMB) + 1L) + " MB";
        if (uBytes <= uTB) return (((uBytes - 1L) / uGB) + 1L) + " GB";

        return (((uBytes - 1L) / uTB) + 1L) + " TB";
    }

    public static String FormatDataSizeKB(long uBytes) {
        final long uKB = 1024;

        if (uBytes == 0) return "0 KB";
        if (uBytes <= uKB) return "1 KB";

        return (((uBytes - 1L) / uKB) + 1L) + " KB";
    }

    private static final Character[] m_vVersionSep = new Character[]{'.', ','};

    public static long ParseVersion(String strVersion) {
        if (strVersion == null) {
            assert false;
            return 0;
        }

        String[] vVer = strVersion.split("[" + Joiner.on("").join(m_vVersionSep) + "]");
        if ((vVer == null) || (vVer.length == 0)) {
            assert false;
            return 0;
        }

        short[] uPart = new short[1];
        StrUtil.TryParseUShort(vVer[0].trim(), uPart);
        long uVer = ((long) uPart[0] << 48);

        if (vVer.length >= 2) {
            StrUtil.TryParseUShort(vVer[1].trim(), uPart);
            uVer |= ((long) uPart[0] << 32);
        }

        if (vVer.length >= 3) {
            StrUtil.TryParseUShort(vVer[2].trim(), uPart);
            uVer |= ((long) uPart[0] << 16);
        }

        if (vVer.length >= 4) {
            StrUtil.TryParseUShort(vVer[3].trim(), uPart);
            uVer |= (long) uPart[0];
        }

        return uVer;
    }

    public static String VersionToString(long uVersion) {
        return VersionToString(uVersion, 1);
    }

    //[Obsolete]
    public static String VersionToString(long uVersion,
                                         boolean bEnsureAtLeastTwoComp) {
        return VersionToString(uVersion, (bEnsureAtLeastTwoComp ? 2 : 1));
    }

    public static String VersionToString(long uVersion, int uMinComp) {
        StringBuilder sb = new StringBuilder();
        int uComp = 0;

        for (int i = 0; i < 4; ++i) {
            if (uVersion == 0L) break;

            short us = (short) (uVersion >> 48);

            if (sb.length() > 0) sb.append('.');

            sb.append(us);
            ++uComp;

            uVersion <<= 16;
        }

        while (uComp < uMinComp) {
            if (sb.length() > 0) sb.append('.');

            sb.append('0');
            ++uComp;
        }

        return sb.toString();
    }

    private static final byte[] m_pbOptEnt = {(byte) 0xA5, 0x74, 0x2E, (byte) 0xEC};

    public static String EncryptString(String strPlainText) {
        if (Strings.isNullOrEmpty(strPlainText)) return "";

        try {
            byte[] pbPlain = strPlainText.getBytes(Charsets.UTF_8);
//            byte[] pbEnc = ProtectedData.Protect(pbPlain, m_pbOptEnt,
//                    DataProtectionScope.CurrentUser);

            byte[] pbEnc = pbPlain;
            return BaseEncoding.base64().encode(pbEnc);
        } catch (Exception e) {
            assert false;
        }

        return strPlainText;
    }

    public static String DecryptString(String strCipherText) {
        if (Strings.isNullOrEmpty(strCipherText)) return "";

        try {
            byte[] pbEnc = BaseEncoding.base64().decode(strCipherText);
//            byte[] pbPlain = ProtectedData.Unprotect(pbEnc, m_pbOptEnt,
//                    DataProtectionScope.CurrentUser);
            byte[] pbPlain = pbEnc;

            return new String(pbPlain, 0, pbPlain.length, Charsets.UTF_8);
        } catch (Exception e) {
            assert false;
        }

        return strCipherText;
    }

    public static String SerializeIntArray(int[] vNumbers) {
        if (vNumbers == null) throw new IllegalArgumentException("vNumbers");

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < vNumbers.length; ++i) {
            if (i > 0) sb.append(' ');
            sb.append(vNumbers[i]);
        }

        return sb.toString();
    }

    public static int[] DeserializeIntArray(String strSerialized) {
        if (strSerialized == null)
            throw new IllegalArgumentException("strSerialized");
        if (strSerialized.length() == 0) return new int[0];

        String[] vParts = strSerialized.split(" ");
        int[] v = new int[vParts.length];

        for (int i = 0; i < vParts.length; ++i) {
            int[] n = new int[1];
            if (!TryParseIntInvariant(vParts[i], n)) {
                assert false;
            }
            v[i] = n[0];
        }

        return v;
    }

    private static final Character[] m_vTagSep = new Character[]{',', ';', ':'};

    public static String TagsToString(List<String> vTags, boolean bForDisplay) {
        if (vTags == null) throw new IllegalArgumentException("vTags");

        StringBuilder sb = new StringBuilder();
        boolean bFirst = true;

        for (String strTag : vTags) {
            if (Strings.isNullOrEmpty(strTag)) {
                assert false;
                continue;
            }

            if (!bFirst) {
                if (bForDisplay) sb.append(", ");
                else sb.append(';');
            }
            sb.append(strTag);

            bFirst = false;
        }

        return sb.toString();
    }

    public static List<String> StringToTags(String strTags) {
        if (strTags == null) throw new IllegalArgumentException("strTags");

        List<String> lTags = new ArrayList<String>();
        if (strTags.length() == 0) return lTags;

        String[] vTags = strTags.split("[" + Joiner.on("").join(m_vTagSep) + "]");
        for (String strTag : vTags) {
            String strFlt = strTag.trim();
            if (strFlt.length() > 0) lTags.add(strFlt);
        }

        return lTags;
    }

    public static String Obfuscate(String strPlain) {
        if (strPlain == null) {
            assert false;
            return "";
        }
        if (strPlain.length() == 0) return "";

        byte[] pb = strPlain.getBytes(Charsets.UTF_8);

        ArraysReverse(pb);
        for (int i = 0; i < pb.length; ++i) pb[i] = (byte) (pb[i] ^ 0x65);

        return BaseEncoding.base64().encode(pb);
    }

    public static String Deobfuscate(String strObf) {
        if (strObf == null) {
            assert false;
            return "";
        }
        if (strObf.length() == 0) return "";

        try {
            byte[] pb = BaseEncoding.base64().decode(strObf);

            for (int i = 0; i < pb.length; ++i) pb[i] = (byte) (pb[i] ^ 0x65);
            ArraysReverse(pb);

            return new String(pb, 0, pb.length, Charsets.UTF_8);
        } catch (Exception e) {
            assert false;
        }

        return "";
    }

    /// <summary>
    /// Split a String and include the separators in the splitted array.
    /// </summary>
    /// <param name="str">String to split.</param>
    /// <param name="vSeps">Separators.</param>
    /// <param name="bCaseSensitive">Specifies whether separators are
    /// matched case-sensitively or not.</param>
    /// <returns>Splitted String including separators.</returns>
    public static List<String> SplitWithSep(String str, String[] vSeps,
                                            boolean bCaseSensitive) {
        if (str == null) throw new IllegalArgumentException("str");
        if (vSeps == null) throw new IllegalArgumentException("vSeps");

        List<String> v = new ArrayList<String>();
        while (true) {
            int minIndex = Integer.MAX_VALUE, minSep = -1;
            for (int i = 0; i < vSeps.length; ++i) {
                String strSep = vSeps[i];
                if (Strings.isNullOrEmpty(strSep)) {
                    assert false;
                    continue;
                }

                int iIndex = (bCaseSensitive ? str.indexOf(strSep) :
                        str.toLowerCase().indexOf(strSep.toLowerCase()));
                if ((iIndex >= 0) && (iIndex < minIndex)) {
                    minIndex = iIndex;
                    minSep = i;
                }
            }

            if (minIndex == Integer.MAX_VALUE) break;

            v.add(str.substring(0, minIndex));
            v.add(vSeps[minSep]);

            str = str.substring(minIndex + vSeps[minSep].length());
        }

        v.add(str);
        return v;
    }

    public static String MultiToSingleLine(String strMulti) {
        if (strMulti == null) {
            assert false;
            return "";
        }
        if (strMulti.length() == 0) return "";

        String str = strMulti;
        str = str.replace("\r\n", " ");
        str = str.replace("\r", " ");
        str = str.replace("\n", " ");

        return str;
    }

    public static List<String> SplitSearchTerms(String strSearch) {
        List<String> l = new ArrayList<String>();
        if (strSearch == null) {
            assert false;
            return l;
        }

        StringBuilder sbTerm = new StringBuilder();
        boolean bQuoted = false;

        for (int i = 0; i < strSearch.length(); ++i) {
            char ch = strSearch.charAt(i);

            if (((ch == ' ') || (ch == '\t') || (ch == '\r') ||
                    (ch == '\n')) && !bQuoted) {
                if (sbTerm.length() > 0) l.add(sbTerm.toString());

                sbTerm.delete(0, sbTerm.length());
            } else if (ch == '\"') bQuoted = !bQuoted;
            else sbTerm.append(ch);
        }
        if (sbTerm.length() > 0) l.add(sbTerm.toString());

        return l;
    }

    public static Comparator<String> CompareLengthGt = new Comparator<String>() {
        public int compare(String x, String y) {
            if (x.length() == y.length()) return 0;
            return ((x.length() > y.length()) ? -1 : 1);
        }
    };
    public static Comparator<String> CaseIgnoreComparer = new Comparator<String>() {
        public int compare(String x, String y) {
            return x.toLowerCase().compareTo(y.toLowerCase());
        }
    };

    public static boolean IsDataUri(String strUri) {
        return IsDataUri(strUri, null);
    }

    public static boolean IsDataUri(String strUri, String strReqMimeType) {
        if (strUri == null) {
            assert false;
            return false;
        }
        // strReqMimeType may be null

        final String strPrefix = "data:";
        if (!strUri.toLowerCase().startsWith(strPrefix))
            return false;

        int iC = strUri.indexOf(',');
        if (iC < 0) return false;

        if (!Strings.isNullOrEmpty(strReqMimeType)) {
            int iS = strUri.indexOf(';', iC);
            int iTerm = ((iS >= 0) ? iS : iC);

            String strMime = strUri.substring(strPrefix.length(),
                    iTerm - strPrefix.length());
            if (!strMime.equalsIgnoreCase(strReqMimeType))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Create a data URI (according to RFC 2397).
    /// </summary>
    /// <param name="pbData">Data to encode.</param>
    /// <param name="strMimeType">Optional MIME type. If <c>null</c>,
    /// an appropriate type is used.</param>
    /// <returns>Data URI.</returns>
    public static String DataToDataUri(byte[] pbData, String strMimeType) {
        if (pbData == null) throw new IllegalArgumentException("pbData");

        if (strMimeType == null) strMimeType = "application/octet-stream";

        return ("data:" + strMimeType + ";base64," + BaseEncoding.base64().encode(
                pbData));
    }

    /// <summary>
    /// Convert a data URI (according to RFC 2397) to binary data.
    /// </summary>
    /// <param name="strDataUri">Data URI to decode.</param>
    /// <returns>Decoded binary data.</returns>
    public static byte[] DataUriToData(String strDataUri) {
        if (strDataUri == null)
            throw new IllegalArgumentException("strDataUri");
        if (!strDataUri.toLowerCase().startsWith("data:")) return null;

        int iSep = strDataUri.indexOf(',');
        if (iSep < 0) return null;

        String strDesc = strDataUri.substring(5, iSep - 5);
        boolean bBase64 = strDesc.toLowerCase().endsWith(";base64");

        String strData = strDataUri.substring(iSep + 1);

        if (bBase64) return BaseEncoding.base64().decode(strData);

        ByteArrayOutputStream ms = new ByteArrayOutputStream();

        Charset enc = Charsets.US_ASCII;
        String[] v = strData.split("%");
        byte[] pb = v[0].getBytes(enc);
        ms.write(pb, 0, pb.length);
        for (int i = 1; i < v.length; ++i) {
            ms.write(Integer.parseInt(v[i].substring(0, 2), 16));
            pb = v[i].substring(2).getBytes(enc);
            ms.write(pb, 0, pb.length);
        }

        pb = ms.toByteArray();
        return pb;
    }

    /// <summary>
    /// Remove placeholders from a String (wrapped in '{' and '}').
    /// This doesn't remove environment variables (wrapped in '%').
    /// </summary>
    public static String RemovePlaceholders(String str) {
        if (str == null) {
            assert false;
            return "";
        }

        while (true) {
            int iPlhStart = str.indexOf('{');
            if (iPlhStart < 0) break;

            int iPlhEnd = str.indexOf('}', iPlhStart); // '{' might be at end
            if (iPlhEnd < 0) break;

            str = (str.substring(0, iPlhStart) + str.substring(iPlhEnd + 1));
        }

        return str;
    }

    public static StrEncodingInfo GetEncoding(StrEncodingType t) {
        for (StrEncodingInfo sei : StrUtil.getEncodings()) {
            if (sei.getType() == t) return sei;
        }

        return null;
    }

    public static StrEncodingInfo GetEncoding(String strName) {
        for (StrEncodingInfo sei : StrUtil.getEncodings()) {
            if (strName.equals(sei.getName())) return sei;
        }

        return null;
    }

    private static String[] m_vPrefSepChars = null;

    /// <summary>
    /// Find a character that does not occur within a given text.
    /// </summary>
    public static char GetUnusedChar(String strText) {
        if (strText == null) {
            assert false;
            return '@';
        }

        if (m_vPrefSepChars == null)
            m_vPrefSepChars = new String[]{
                    "@!$%#/\\:;,.*-_?",
                    PwCharSet.UpperCase, PwCharSet.LowerCase,
                    PwCharSet.Digits, PwCharSet.PrintableAsciiSpecial
            };

        for (String m_vPrefSepChar : m_vPrefSepChars) {
            for (char ch : m_vPrefSepChar.toCharArray()) {
                if (strText.indexOf(ch) < 0) return ch;
            }
        }

        for (char ch = '\u00C0'; ch < Character.MAX_VALUE; ++ch) {
            if (strText.indexOf(ch) < 0) return ch;
        }

        return Character.MIN_VALUE;
    }

    public static char ByteToSafeChar(byte _bt) {
        final char chDefault = '.';
        int bt = _bt & 0xff;

        // 00-1F are C0 control chars
        if (bt < 0x20) return chDefault;

        // 20-7F are basic Latin; 7F is DEL
        if (bt < 0x7F) return (char) bt;

        // 80-9F are C1 control chars
        if (bt < 0xA0) return chDefault;

        // A0-FF are Latin-1 supplement; AD is soft hyphen
        if (bt == 0xAD) return '-';
        return (char) bt;
    }

    public static int Count(String str, String strNeedle) {
        if (str == null) {
            assert false;
            return 0;
        }
        if (Strings.isNullOrEmpty(strNeedle)) {
            assert false;
            return 0;
        }

        int iOffset = 0, iCount = 0;
        while (iOffset < str.length()) {
            int p = str.indexOf(strNeedle, iOffset);
            if (p < 0) break;

            ++iCount;
            iOffset = p + 1;
        }

        return iCount;
    }

    public static byte[] ArraysReverse(byte[] array) {
        for(int i = 0; i < array.length / 2; i++)
        {
            byte temp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = temp;
        }
        return array;
    }
}
