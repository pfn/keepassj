package com.hanhuy.keepassj.spr;

import java.util.EventObject;

public class SprEventArgs extends EventObject
{
    private String m_str = "";
    public String getText()
    {
        return m_str;
    }
    public void setText(String value)
    {
        if(value == null) throw new IllegalArgumentException("value");
        m_str = value;
    }

    private SprContext m_ctx = null;
    public SprContext getContext()
    {
        return m_ctx;
    }

    public SprEventArgs() {
        super(null);
    }

    public SprEventArgs(String strText, SprContext ctx)
    {
        super(null);
        if(strText == null) throw new IllegalArgumentException("strText");
        // ctx == null is allowed

        m_str = strText;
        m_ctx = ctx;
    }
}
