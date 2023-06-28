/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.demo.controller;

import com.example.demo.bean.HashFileRequest;
import com.example.demo.bean.HashFileResponse;
import com.example.demo.bean.UploadSignatureRequest;
import com.example.demo.bean.UploadSignatureResponse;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.URI;

/**
 *
 * @author Chungnv
 */
@RestController

public class UploadController {

    @Autowired
    private HttpServletRequest request;

    @RequestMapping(value = "/uploadbase64", method = RequestMethod.POST)
    public ResponseEntity uploadbase64(@RequestBody String data, @RequestHeader("fileName") String fileName) throws IOException {

        byte[] binaryData = Base64.decodeBase64(data);
        File file = new File("Signed_" + fileName);
        try (OutputStream stream = new FileOutputStream(file)) {
            stream.write(binaryData);
        }
        return ResponseEntity.ok(file.getAbsolutePath());
    }

    @RequestMapping(value = "/upload", method = RequestMethod.POST)
    public ResponseEntity upload(HttpSession session, @RequestParam("uploadFile") MultipartFile uploadFile,
            @RequestParam("certificateChain") String certificateChain) throws IOException, Exception {
        String filePath = request.getServletContext().getRealPath("/");
        String fileName = uploadFile.getOriginalFilename();
        File file = new File(filePath + fileName);
        uploadFile.transferTo(file);
        RestTemplate restTemplate = new RestTemplate();
        URI uri = new URI("http://localhost:8888/hashFile/");
        HashFileRequest hashFileRequest = new HashFileRequest();
        hashFileRequest.setSourceFilePath(file.getAbsolutePath());
        hashFileRequest.setCertificateChain(certificateChain);
        ResponseEntity<HashFileResponse> result = restTemplate.postForEntity(uri, hashFileRequest, HashFileResponse.class);
        HashFileResponse hashFileResponse = result.getBody();
        session.setAttribute("TransactionId", hashFileResponse.getTransactionId());
        session.setAttribute("FileName", fileName);
        UploadFileAndCertResponse uploadFileAndCertResponse = new UploadFileAndCertResponse(hashFileResponse.getData(), hashFileResponse.getSerial());
        return ResponseEntity.ok(uploadFileAndCertResponse);

    }

    @RequestMapping(value = "/uploadSignature", method = RequestMethod.POST)
    public ResponseEntity uploadSignature(HttpSession session, @RequestBody String signature) throws IOException, Exception {
        Long transactionId = (Long) session.getAttribute("TransactionId");
        String fileName = (String) session.getAttribute("FileName");
        String descFile = "Signed_" + fileName;
        File desc = new File(descFile);
        RestTemplate restTemplate = new RestTemplate();
        URI uri = new URI("http://localhost:8888/uploadSignature/");
        UploadSignatureRequest uploadSignatureRequest = new UploadSignatureRequest();
        uploadSignatureRequest.setTransactionId(transactionId);
        uploadSignatureRequest.setSignature(signature);
        uploadSignatureRequest.setSignedFile(descFile);
        ResponseEntity<UploadSignatureResponse> result = restTemplate.postForEntity(uri, uploadSignatureRequest, UploadSignatureResponse.class);
        System.out.println(result.getBody());
        String response = "Sign success. <a href='/files/" + desc.getName() + "' >Download</a> " + descFile;
        return ResponseEntity.ok(response);
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
