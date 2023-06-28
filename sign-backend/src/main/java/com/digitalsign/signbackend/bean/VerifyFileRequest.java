package com.digitalsign.signbackend.bean;

public class VerifyFileRequest {
    String sourceFilePath;


    public String getSourceFilePath() {
        return sourceFilePath;
    }

    public void setSourceFilePath(String sourceFilePath) {
        this.sourceFilePath = sourceFilePath;
    }

    @Override
    public String toString() {
        return "VerifyFileRequest{" +
                "sourceFilePath='" + sourceFilePath + '\'' +
                '}';
    }
}
