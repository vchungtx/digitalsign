package com.digitalsign.signbackend.service;

import com.digitalsign.signbackend.bean.HashFileRequest;
import com.digitalsign.signbackend.bean.HashFileResponse;
import com.digitalsign.signbackend.bean.UploadSignatureRequest;
import com.digitalsign.signbackend.bean.UploadSignatureResponse;
import com.digitalsign.signbackend.database.entity.TransactionEntity;
import com.digitalsign.signbackend.database.repository.TransactionRepository;
import com.digitalsign.signbackend.signature.plugin.IFileSigner;
import com.digitalsign.signbackend.signature.plugin.SignOOXmlFile;
import com.digitalsign.signbackend.signature.plugin.SignPdfFile;
import com.digitalsign.signbackend.signature.plugin.SignXmlFile;
import com.digitalsign.signbackend.signature.utils.Utils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Date;


@Service
public class SignService {

    private static final Logger logger = LoggerFactory.getLogger(SignService.class);

    @Autowired
    TransactionRepository transactionRepository;

    public HashFileResponse hashFile(HashFileRequest request) throws Exception{
        logger.info("hashFile Request:" + request);
        HashFileResponse hashFileResponse = new HashFileResponse(ErrorCode.ERR_COMMON.code(), ErrorCode.ERR_COMMON.message());
        File file = new File(request.getSourceFilePath());
        if (!file.exists()) {
            return new HashFileResponse(ErrorCode.ERR_COMMON.code(), "File Not found");
        }
        Gson gson = new GsonBuilder()
        .registerTypeAdapter(Date.class, (JsonDeserializer<Date>) (json, typeOfT, context) -> new Date(json.getAsJsonPrimitive().getAsLong()))
        .registerTypeAdapter(Date.class, (JsonSerializer<Date>) (date, type, jsonSerializationContext) -> new JsonPrimitive(date.getTime()))
        .create();
        
        String fileName = file.getName();
        X509Certificate[] chain = Utils.getX509Chain(request.getCertificateChain());
//        VerifyCert verifyCert = new VerifyCert();
//        verifyCert.verifyChain(chain);
        TransactionEntity transactionEntity = new TransactionEntity();
        transactionEntity.setSourceFile(file.getAbsolutePath());
        transactionEntity.setCreatedDate(new Date());
        transactionEntity.setCertificateChain(request.getCertificateChain());
        if (fileName.toLowerCase().endsWith(".pdf")) {
            SignPdfFile signPdfFile = new SignPdfFile();
            String base64Data = signPdfFile.createHash(file.getAbsolutePath(), chain);
            transactionEntity.setFileType(Constant.FILE_TYPE_PDF);
            transactionEntity.setData(gson.toJson(signPdfFile));
            transactionEntity.setTempFile(signPdfFile.getTmpFile());
            transactionRepository.save(transactionEntity);
            hashFileResponse.setTransactionId(transactionEntity.getTransactionId());
            hashFileResponse.setErrorCode(ErrorCode.SUCCESS.code());
            hashFileResponse.setErrorDesc(ErrorCode.SUCCESS.message());
            hashFileResponse.setData(base64Data);
            hashFileResponse.setSerial(Hex.toHexString(chain[0].getSerialNumber().toByteArray()));
        }else if (fileName.toLowerCase().endsWith(".docx") || fileName.toLowerCase().endsWith(".xlsx") || fileName.toLowerCase().endsWith(".pptx")) {
            SignOOXmlFile signOOXmlFile = new SignOOXmlFile();
            String base64Data = signOOXmlFile.createHash(file.getAbsolutePath(), chain);
            transactionEntity.setFileType(Constant.FILE_TYPE_OOXML);
            transactionEntity.setData(gson.toJson(signOOXmlFile));
            transactionRepository.save(transactionEntity);
            hashFileResponse.setTransactionId(transactionEntity.getTransactionId());
            hashFileResponse.setErrorCode(ErrorCode.SUCCESS.code());
            hashFileResponse.setErrorDesc(ErrorCode.SUCCESS.message());
            hashFileResponse.setData(base64Data);
            hashFileResponse.setSerial(Hex.toHexString(chain[0].getSerialNumber().toByteArray()));
        } else if (fileName.toLowerCase().endsWith(".xml")) {
            SignXmlFile signXmlFile = new SignXmlFile();
            String base64Data = signXmlFile.createHash(file.getAbsolutePath(), chain);
            transactionEntity.setFileType(Constant.FILE_TYPE_XML);
            transactionEntity.setData(gson.toJson(signXmlFile));
            transactionRepository.save(transactionEntity);
            hashFileResponse.setTransactionId(transactionEntity.getTransactionId());
            hashFileResponse.setErrorCode(ErrorCode.SUCCESS.code());
            hashFileResponse.setErrorDesc(ErrorCode.SUCCESS.message());
            hashFileResponse.setData(base64Data);
            hashFileResponse.setSerial(Hex.toHexString(chain[0].getSerialNumber().toByteArray()));
        }else{
            hashFileResponse.setErrorDesc("Filetype is not supported");
        }
        logger.info("hashFile Response:" + hashFileResponse);
        return hashFileResponse ;
    }


    public UploadSignatureResponse uploadSignature(UploadSignatureRequest request) throws Exception{
        logger.info("uploadSignature Request:" + request);
        Gson gson = new GsonBuilder()
        .registerTypeAdapter(Date.class, (JsonDeserializer<Date>) (json, typeOfT, context) -> new Date(json.getAsJsonPrimitive().getAsLong()))
        .registerTypeAdapter(Date.class, (JsonSerializer<Date>) (date, type, jsonSerializationContext) -> new JsonPrimitive(date.getTime()))
        .create();
        UploadSignatureResponse uploadSignatureResponse = new UploadSignatureResponse(ErrorCode.ERR_COMMON.code(), ErrorCode.ERR_COMMON.message());
        TransactionEntity transaction = transactionRepository.getReferenceById(request.getTransactionId());
        if (transaction == null){
            uploadSignatureResponse.setErrorDesc("Transaction not found");
        }else{
            File signedFile = new File(request.getSignedFile());
            X509Certificate[] chain = Utils.getX509Chain(transaction.getCertificateChain());
            IFileSigner fileSigner;
            if (Constant.FILE_TYPE_PDF.equals(transaction.getFileType())){
                fileSigner = gson.fromJson(transaction.getData(), SignPdfFile.class);

            }else if (Constant.FILE_TYPE_OOXML.equals(transaction.getFileType())){
                fileSigner = gson.fromJson(transaction.getData(), SignOOXmlFile.class);

            }else if (Constant.FILE_TYPE_XML.equals(transaction.getFileType())){
                fileSigner = gson.fromJson(transaction.getData(), SignXmlFile.class);

            }else{
                uploadSignatureResponse.setErrorDesc("Filetype is not supported");
                return uploadSignatureResponse;
            }
            boolean success = fileSigner.insertSignature(request.getSignature(), signedFile.getAbsolutePath(), chain);
            if (success){
                transaction.setSignedFile(signedFile.getAbsolutePath());
                transactionRepository.save(transaction);
                uploadSignatureResponse.setErrorCode(ErrorCode.SUCCESS.code());
                uploadSignatureResponse.setErrorDesc(ErrorCode.SUCCESS.message());
            }else {
                uploadSignatureResponse.setErrorCode(ErrorCode.ERR_COMMON.code());
                uploadSignatureResponse.setErrorDesc(ErrorCode.ERR_COMMON.message());
            }
        }
        logger.info("uploadSignature Response:" + uploadSignatureResponse);
        return uploadSignatureResponse ;
    }
}
