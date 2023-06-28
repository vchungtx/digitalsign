/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.demo.bean;

/**
 *
 * @author Chungnv
 */
public class UploadSignatureResponse {
    long transactionId;
    String errorCode;
    String errorDesc;

    public UploadSignatureResponse() {
    }

    public UploadSignatureResponse(String errorCode, String errorDesc) {
        this.errorCode = errorCode;
        this.errorDesc = errorDesc;
    }

    public UploadSignatureResponse(long transactionId, String errorCode, String errorDesc, String data, String serial) {
        this.transactionId = transactionId;
        this.errorCode = errorCode;
        this.errorDesc = errorDesc;
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


}
