package com.hanhuy.keepassj;

/**
 * @author pfnguyen
 */
public class InvalidCompositeKeyException extends RuntimeException
{
    public InvalidCompositeKeyException() {
    }

    public InvalidCompositeKeyException(String message) {
        super(message);
    }
}
