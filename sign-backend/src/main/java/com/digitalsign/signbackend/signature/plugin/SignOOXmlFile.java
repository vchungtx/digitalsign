/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.signature.plugin;


import java.security.cert.Certificate;
import java.util.Date;

import com.digitalsign.signbackend.signature.ooxml.OoxmlDigitalSignature;
import org.apache.tomcat.util.codec.binary.Base64;

/**
 *
 * @author chungnv14
 */
public class SignOOXmlFile implements IFileSigner {

//    private Certificate[] chain;
    private String filePath;
    private Date signedDate;
    @Override
    public String createHash(String filePath, Certificate[] chain) throws Exception {
        OoxmlDigitalSignature xlsxSignature = new OoxmlDigitalSignature(null, chain);
//        this.chain = chain;
        this.filePath = filePath;
        this.signedDate = new Date();
        byte[] hash = xlsxSignature.createHash(filePath, signedDate);
        return Base64.encodeBase64String(hash);
    }

    @Override
    public boolean insertSignature(String extSig, String destFile, Certificate[] chain) throws Exception {
        OoxmlDigitalSignature xlsxSignature = new OoxmlDigitalSignature(null, chain);
        return xlsxSignature.insertSignature(Base64.decodeBase64(extSig), destFile, filePath, signedDate);

    }

}
