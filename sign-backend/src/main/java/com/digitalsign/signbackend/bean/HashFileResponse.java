/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.bean;

/**
 *
 * @author Chungnv
 */
public class HashFileResponse {
    long transactionId;
    String errorCode;
    String errorDesc;
    String data;
    String serial;

    public HashFileResponse() {
    }

    public HashFileResponse(String errorCode, String errorDesc) {
        this.errorCode = errorCode;
        this.errorDesc = errorDesc;
    }

    public HashFileResponse(long transactionId, String errorCode, String errorDesc, String data, String serial) {
        this.transactionId = transactionId;
        this.errorCode = errorCode;
        this.errorDesc = errorDesc;
        this.data = data;
        this.serial = serial;
    }

    public long getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(long transactionId) {
        this.transactionId = transactionId;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorDesc() {
        return errorDesc;
    }

    public void setErrorDesc(String errorDesc) {
        this.errorDesc = errorDesc;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSerial() {
        return serial;
    }

    public void setSerial(String serial) {
        this.serial = serial;
    }

    @Override
    public String toString() {
        return "HashFileResponse{" +
                "transactionId=" + transactionId +
                ", errorCode='" + errorCode + '\'' +
                ", errorDesc='" + errorDesc + '\'' +
                ", data='" + data + '\'' +
                ", serial='" + serial + '\'' +
                '}';
    }
}
