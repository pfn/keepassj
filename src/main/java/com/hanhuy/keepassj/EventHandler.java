package com.hanhuy.keepassj;

import java.util.EventObject;

/**
 * @author pfnguyen
 */
public interface EventHandler<T extends EventObject> {
    public void delegate(Object sender, T e);
}
