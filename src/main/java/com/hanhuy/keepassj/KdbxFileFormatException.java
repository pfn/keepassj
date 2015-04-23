package com.hanhuy.keepassj;

/**
 * @author pfnguyen
 */
public class KdbxFileFormatException extends RuntimeException {
    public KdbxFileFormatException(String message) {
        super(message);
    }

    public KdbxFileFormatException(Throwable cause) {
        super(cause);
    }
}
