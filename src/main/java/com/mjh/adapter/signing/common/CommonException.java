package com.mjh.adapter.signing.common;

public class CommonException extends Exception {

    private static final long serialVersionUID = 1L;

    public CommonException(String message) {
        super(message);
    }

    public CommonException(String message, Throwable e) {
        super(message, e);
    }
}
