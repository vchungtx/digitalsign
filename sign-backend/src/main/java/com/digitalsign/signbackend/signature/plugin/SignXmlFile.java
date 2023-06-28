/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.signature.plugin;


import java.io.File;
import java.security.MessageDigest;
import java.security.cert.Certificate;

import com.digitalsign.signbackend.signature.xml.XmlDigitalSignature;
import org.apache.tomcat.util.codec.binary.Base64;

/**
 * @author chungnv14
 */
public class SignXmlFile implements IFileSigner {
    private String tmpFile;

    @Override
    public String createHash(String filePath, Certificate[] chain) throws Exception {
        XmlDigitalSignature xmlSignature = new XmlDigitalSignature();
        File tempFile = File.createTempFile("temp", ".xml");
        byte[] hash = xmlSignature.createDigest(filePath, tempFile.getAbsolutePath(), chain);
        this.tmpFile = tempFile.getAbsolutePath();
        return Base64.encodeBase64String(encodeData(hash, "SHA1"));
    }

    @Override
    public boolean insertSignature(String extSig, String destFile, Certificate[] chain) throws Exception {

        XmlDigitalSignature xmlSignature = new XmlDigitalSignature();
        xmlSignature.insertSignature(tmpFile, destFile, Base64.decodeBase64(extSig));
        return true;

    }

    private byte[] encodeData(byte[] orginalData, String algorithm) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(orginalData);
    }


}
