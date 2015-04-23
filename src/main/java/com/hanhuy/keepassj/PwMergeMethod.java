package com.hanhuy.keepassj;

/**
* @author pfnguyen
*/ /// <summary>
/// Methods for merging password databases/entries.
/// </summary>
public enum PwMergeMethod
{
    // Do not change the explicitly assigned values, otherwise
    // serialization (e.g. of Ecas triggers) breaks
    None,
    OverwriteExisting,
    KeepExisting,
    OverwriteIfNewer,
    CreateNewUuids,
    Synchronize
}
