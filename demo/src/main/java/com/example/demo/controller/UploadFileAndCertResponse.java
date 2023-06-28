/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.demo.controller;

/**
 *
 * @author Chungnv
 */
public class UploadFileAndCertResponse {
    String data;
    String serial;

    public UploadFileAndCertResponse() {
    }

    public UploadFileAndCertResponse(String data, String serial) {
        this.data = data;
        this.serial = serial;
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
    
    
}
