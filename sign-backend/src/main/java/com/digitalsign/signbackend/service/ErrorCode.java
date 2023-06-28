/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.service;

import java.util.HashMap;
import java.util.Map;

/**
 * @author chungnv
 */
public enum ErrorCode {
    SUCCESS(0, "MSG_SUCCESS", "Successfully"),
    ERR_COMMON(1, "ERR_COMMON", "System error, please try again!");



    private final int status;
    private final String code;
    private final String message;

    private static final Map<Integer, ErrorCode> mStatusValues = new HashMap<Integer, ErrorCode>();
    private static final Map<String, ErrorCode> mCodeValues = new HashMap<String, ErrorCode>();

    static {
        for (ErrorCode ec : ErrorCode.values()) {
            mStatusValues.put(ec.status(), ec);
            mCodeValues.put(ec.code(), ec);
        }
    }

    private ErrorCode(int status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }

    public int status() {
        return this.status;
    }

    public String code() {
        return this.code;
    }

    public String message() {
        return this.message;
    }

    public boolean is(int status) {
        return this.status == status;
    }

    public static ErrorCode get(int status) {
        return mStatusValues.get(status);
    }

    public static ErrorCode get(String code) {
        return mCodeValues.get(code);
    }
}
