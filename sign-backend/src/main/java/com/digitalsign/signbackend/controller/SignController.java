/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.controller;


import com.digitalsign.signbackend.bean.HashFileRequest;
import com.digitalsign.signbackend.bean.UploadSignatureRequest;
import com.digitalsign.signbackend.service.SignService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Chungnv
 */
@RestController

public class SignController {


    @Autowired
    SignService signService;

    @RequestMapping(value = "/hashFile", method = RequestMethod.POST)
    public ResponseEntity upload(@RequestBody HashFileRequest request) throws IOException, Exception {

        return ResponseEntity.ok(signService.hashFile(request));


    }

    @RequestMapping(value = "/uploadSignature", method = RequestMethod.POST)
    public ResponseEntity uploadSignature(@RequestBody UploadSignatureRequest request) throws IOException, Exception {
        return ResponseEntity.ok(signService.uploadSignature(request));
    }

    @RequestMapping(value = "/files/{file_name}", method = RequestMethod.GET)
    public void getFile(
            @PathVariable("file_name") String fileName,
            HttpServletResponse response) {
        try {
            // get your file as InputStream
            File desc = new File(fileName);
            InputStream is = new FileInputStream(desc);
            // copy it to response's OutputStream
            org.apache.commons.io.IOUtils.copy(is, response.getOutputStream());
            response.flushBuffer();
        } catch (IOException ex) {

            throw new RuntimeException("IOError writing file to output stream");
        }

    }
}
