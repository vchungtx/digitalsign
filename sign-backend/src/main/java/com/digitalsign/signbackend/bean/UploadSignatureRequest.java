package com.digitalsign.signbackend.bean;

public class UploadSignatureRequest {
    long transactionId;
    String signature;
    String signedFile;
    public long getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(long transactionId) {
        this.transactionId = transactionId;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSignedFile() {
        return signedFile;
    }

    public void setSignedFile(String signedFile) {
        this.signedFile = signedFile;
    }
}
