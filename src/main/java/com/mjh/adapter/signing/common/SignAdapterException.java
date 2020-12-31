package com.mjh.adapter.signing.common;

import java.security.GeneralSecurityException;

public class SignAdapterException extends GeneralSecurityException {
    private static final long serialVersionUID = 7718828512143293558L;
    private final String code;

    public SignAdapterException(String message, Throwable cause, String code){
        super(message, cause);
        this.code = code;
    }

    public SignAdapterException(String message, String code){
        super(message);
        this.code = code;
    }

    public SignAdapterException(Throwable cause, String code){
        super(cause);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
