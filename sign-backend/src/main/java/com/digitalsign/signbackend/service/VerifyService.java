package com.digitalsign.signbackend.service;

import com.digitalsign.signbackend.bean.VerifyFileRequest;
import com.digitalsign.signbackend.bean.VerifyFileResponse;
import com.digitalsign.signbackend.verify.VerifyOOXML;
import com.digitalsign.signbackend.verify.VerifyPDF;
import com.digitalsign.signbackend.verify.VerifyXML;
import com.google.gson.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.security.Security;
import java.util.Date;


@Service
public class VerifyService {

    private static final Logger logger = LoggerFactory.getLogger(VerifyService.class);


    public VerifyFileResponse verifyFile(VerifyFileRequest request) throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        logger.info("verifyFile Request:" + request);
        VerifyFileResponse verifyFileResponse = new VerifyFileResponse(ErrorCode.ERR_COMMON.code(), ErrorCode.ERR_COMMON.message());
        File file = new File(request.getSourceFilePath());
        if (!file.exists()) {
            return new VerifyFileResponse(ErrorCode.ERR_COMMON.code(), "File Not found");
        }
        String fileName = file.getName();
        if (fileName.toLowerCase().endsWith(".pdf")) {
            VerifyPDF verifyPDF = new VerifyPDF();
            verifyFileResponse.setVerifiers(verifyPDF.verifySignatures(file.getAbsolutePath()));
            verifyFileResponse.setErrorCode(ErrorCode.SUCCESS.code());
            verifyFileResponse.setErrorDesc(ErrorCode.SUCCESS.message());
        } else if (fileName.toLowerCase().endsWith(".docx") || fileName.toLowerCase().endsWith(".xlsx") || fileName.toLowerCase().endsWith(".pptx")) {
            VerifyOOXML verifyOOXML = new VerifyOOXML();
            verifyFileResponse.setVerifiers(verifyOOXML.verify(file.toURI().toURL()));
            verifyFileResponse.setErrorCode(ErrorCode.SUCCESS.code());
            verifyFileResponse.setErrorDesc(ErrorCode.SUCCESS.message());
        } else if (fileName.toLowerCase().endsWith(".xml")) {
            VerifyXML verifyXML = new VerifyXML();
            verifyFileResponse.setVerifiers(verifyXML.verifySignatures(file.getAbsolutePath()));
            verifyFileResponse.setErrorCode(ErrorCode.SUCCESS.code());
            verifyFileResponse.setErrorDesc(ErrorCode.SUCCESS.message());
        } else {
            verifyFileResponse.setErrorDesc("Filetype is not supported");
        }
        return verifyFileResponse;
    }


}
