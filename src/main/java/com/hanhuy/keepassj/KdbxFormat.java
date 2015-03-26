package com.hanhuy.keepassj;

/**
 * @author pfnguyen
 */
/// <summary>
/// The <c>KdbxFile</c> class supports saving the data to various
/// formats.
/// </summary>
public enum KdbxFormat {
    /// <summary>
    /// The default, encrypted file format.
    /// </summary>
    Default,

    /// <summary>
    /// Use this flag when exporting data to a plain-text XML file.
    /// </summary>
    PlainXml
}
