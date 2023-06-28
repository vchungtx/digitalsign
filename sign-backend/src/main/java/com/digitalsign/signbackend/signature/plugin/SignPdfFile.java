/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.signature.plugin;

import java.io.File;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.List;

import com.digitalsign.signbackend.service.SignService;
import com.digitalsign.signbackend.signature.pdf.PdfDeferredSigning;
import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author chungnv14
 */
public class SignPdfFile implements IFileSigner {

    private static final Logger logger = LoggerFactory.getLogger(SignPdfFile.class);
    private String tmpFile;
    private byte[] hash;
//    private Certificate[] chain;
    private String fieldName;

    @Override
    public String createHash(String filePath, Certificate[] chain) {
        try {
            PdfDeferredSigning pdfSig = new PdfDeferredSigning();
            File tempFile = File.createTempFile("temp", ".pdf");
            fieldName = "" + System.currentTimeMillis();
            List<byte[]> lstHash = pdfSig.createHash(filePath, tempFile.getAbsolutePath(),
                    fieldName, chain);
            if (lstHash == null) {
                return null;
            }

            this.tmpFile = tempFile.getAbsolutePath();
            this.hash = lstHash.get(1);
//            this.chain = chain;
            return Base64.encodeBase64String(encodeData(lstHash.get(0), "SHA1"));
        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        }
    }

    @Override
    public boolean insertSignature(String extSig, String destFile, Certificate[] chain) {
        try {
            PdfDeferredSigning pdfSig = new PdfDeferredSigning();
            System.out.println("tmpFile path :" + tmpFile);
            File fileTemp = new File(tmpFile);
            if (pdfSig.insertSignature(tmpFile, destFile, fieldName, hash, Base64.decodeBase64(extSig), chain)) {
                if (fileTemp.exists()) {
                    fileTemp.delete();
                }
                return true;
            } else {
                if (fileTemp.exists()) {
                    fileTemp.delete();
                }
                return false;
            }
        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
            return false;
        }
    }

    private byte[] encodeData(byte[] orginalData, String algorithm) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(orginalData);
    }

    public String getTmpFile() {
        return tmpFile;
    }

    public void setTmpFile(String tmpFile) {
        this.tmpFile = tmpFile;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public String getFieldName() {
        return fieldName;
    }

    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }

}
