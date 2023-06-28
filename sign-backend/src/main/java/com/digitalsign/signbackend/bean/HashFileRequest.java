package com.digitalsign.signbackend.bean;

public class HashFileRequest {
    String sourceFilePath;
    String certificateChain;

    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }

    public String getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(String certificateChain) {
        this.certificateChain = certificateChain;
    }

    @Override
    public String toString() {
        return "HashFileRequest{" +
                "sourceFilePath='" + sourceFilePath + '\'' +
                ", certificateChain='" + certificateChain + '\'' +
                '}';
    }
}
