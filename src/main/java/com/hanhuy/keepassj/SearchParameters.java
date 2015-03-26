package com.hanhuy.keepassj;

/**
 * @author pfnguyen
 */
// #pragma warning disable 1591 // Missing XML comments warning
/// <summary>
/// Search parameters for group and entry searches.
/// </summary>
public class SearchParameters implements Cloneable
{
    private String m_strText = "";
    //[DefaultValue("")]
    public String getSearchString()
    {
        return m_strText;
    }
    public void setSearchString(String value)
    {
        if(value == null) throw new IllegalArgumentException("value");
        m_strText = value;
    }

    private boolean m_bRegex = false;
    //[DefaultValue(false)]
    public boolean getRegularExpression()
    {
        return m_bRegex;
    }
    public void setRegularExpression(boolean value) { m_bRegex = value; }

    private boolean m_bSearchInTitles = true;
    //[DefaultValue(true)]
    public boolean getSearchInTitles()
    {
        return m_bSearchInTitles;
    }
    public void setSearchInTitles(boolean value) { m_bSearchInTitles = value; }

    private boolean m_bSearchInUserNames = true;
    //[DefaultValue(true)]
    public boolean getSearchInUserNames()
    {
        return m_bSearchInUserNames;
    }
    public void setSearchInUserNames(boolean value) { m_bSearchInUserNames = value; }

    private boolean m_bSearchInPasswords = false;
    //[DefaultValue(false)]
    public boolean getSearchInPasswords()
    {
        return m_bSearchInPasswords;
    }
    public void setSearchInPasswords(boolean value) { m_bSearchInPasswords = value; }

    private boolean m_bSearchInUrls = true;
    //[DefaultValue(true)]
    public boolean getSearchInUrls()
    {
        return m_bSearchInUrls;
    }
    public void setSearchInUrls(boolean value) { m_bSearchInUrls = value; }

    private boolean m_bSearchInNotes = true;
    //[DefaultValue(true)]
    public boolean getSearchInNotes()
    {
        return m_bSearchInNotes;
    }
    public void setSearchInNotes(boolean value) { m_bSearchInNotes = value; }

    private boolean m_bSearchInOther = true;
    //[DefaultValue(true)]
    public boolean getSearchInOther()
    {
        return m_bSearchInOther;
    }
    public void setSearchInOther(boolean value) { m_bSearchInOther = value; }

    private boolean m_bSearchInUuids = false;
    //[DefaultValue(false)]
    public boolean getSearchInUuids()
    {
        return m_bSearchInUuids;
    }
    public void setSearchInUuids(boolean value) { m_bSearchInUuids = value; }

    private boolean m_bSearchInGroupNames = false;
    //[DefaultValue(false)]
    public boolean getSearchInGroupNames()
    {
        return m_bSearchInGroupNames;
    }
    public void setSearchInGroupNames(boolean value) { m_bSearchInGroupNames = value; }

    private boolean m_bSearchInTags = true;
    //[DefaultValue(true)]
    public boolean getSearchInTags()
    {
        return m_bSearchInTags;
    }
    public void setSearchInTags(boolean value) { m_bSearchInTags = value; }

    private StringComparison m_scType = StringComparison.InvariantCultureIgnoreCase;
    /// <summary>
    /// String comparison type. Specifies the condition when the specified
    /// text matches a group/entry String.
    /// </summary>
    public StringComparison getComparisonMode()
    {
        return m_scType;
    }
    public void setComparisonMode(StringComparison value) { m_scType = value; }

    private boolean m_bExcludeExpired = false;
    //[DefaultValue(false)]
    public boolean getExcludeExpired()
    {
        return m_bExcludeExpired;
    }
    public void setExcludeExpired(boolean value) { m_bExcludeExpired = value; }

    private boolean m_bRespectEntrySearchingDisabled = true;
    //[DefaultValue(true)]
    public boolean getRespectEntrySearchingDisabled()
    {
        return m_bRespectEntrySearchingDisabled;
    }
    public void setRespectEntrySearchingDisabled(boolean value) { m_bRespectEntrySearchingDisabled = value; }

    private StrPwEntryDelegate m_fnDataTrf = null;
    //[XmlIgnore]
    public StrPwEntryDelegate getDataTransformationFn()
    {
        return m_fnDataTrf;
    }
    public void setDataTransformationFn(StrPwEntryDelegate value) { m_fnDataTrf = value; }

    private String m_strDataTrf = "";
    /// <summary>
    /// Only for serialization.
    /// </summary>
    //[DefaultValue("")]
    public String getDataTransformation()
    {
        return m_strDataTrf;
    }
    public void setDataTransformation(String value)
    {
        if(value == null) throw new IllegalArgumentException("value");
        m_strDataTrf = value;
    }

    //[XmlIgnore]
    public static SearchParameters getNone()
    {
        SearchParameters sp = new SearchParameters();

        // sp.m_strText = "";
        // sp.m_bRegex = false;
        sp.m_bSearchInTitles = false;
        sp.m_bSearchInUserNames = false;
        // sp.m_bSearchInPasswords = false;
        sp.m_bSearchInUrls = false;
        sp.m_bSearchInNotes = false;
        sp.m_bSearchInOther = false;
        // sp.m_bSearchInUuids = false;
        // sp.SearchInGroupNames = false;
        sp.m_bSearchInTags = false;
        // sp.m_scType = StringComparison.InvariantCultureIgnoreCase;
        // sp.m_bExcludeExpired = false;
        // m_bRespectEntrySearchingDisabled = true;

        return sp;
    }

    /// <summary>
    /// Construct a new search parameters Object.
    /// </summary>

    public SearchParameters Clone()
    {
        try {
            return (SearchParameters) clone();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
// #pragma warning restore 1591 // Missing XML comments warning
