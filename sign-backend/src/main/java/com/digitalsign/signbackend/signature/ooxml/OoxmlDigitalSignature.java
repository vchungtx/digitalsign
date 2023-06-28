/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */
package com.digitalsign.signbackend.signature.ooxml;

import java.security.cert.X509Certificate;
import be.fedict.eid.applet.service.signer.ooxml.OOXMLProvider;
import be.fedict.eid.applet.service.spi.DigestInfo;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.crypto.Cipher;
import org.apache.tomcat.util.codec.binary.Base64;

public class OoxmlDigitalSignature {

    /**
     * OOXML specification on XML Digital Signature\
     */
    public static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[]{
        0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14};

    /**
     * Class initialed
     */
    private static boolean initialed = false;

    /**
     * PrivateKey for signing
     */
    private PrivateKey privateKey;

    /**
     * To get certificate signed file
     */
    /**
     * chain
     */
    private List<X509Certificate> certificates;
    /*
     * service for client server sign
     */
    private OOXMLSignatureService service;

    public OoxmlDigitalSignature() {
    }

    /**
     * main constructor
     *
     * @param privateKey key to sign
     * @param certificates chain associates with key
     */
    public OoxmlDigitalSignature(PrivateKey privateKey, Certificate[] certificates) {
        this.privateKey = privateKey;
        this.certificates = new ArrayList<X509Certificate>();
        for (Certificate cert : certificates) {
            X509Certificate xc = (X509Certificate) cert;
            this.certificates.add(xc);
        }
        initial();
    }

    /**
     * Must call initial method at least one time.
     */
    public static void initial() {
        if (!initialed) {
            OOXMLProvider.install();
            initialed = true;
        }
    }

    public byte[] createHash(String srcFile, Date signedDate) throws Exception {
        System.out.println("srcFile: " + srcFile);
        File file = new File(srcFile);
        URL fileURL = file.toURI().toURL();
        service = new OOXMLSignatureService(fileURL, signedDate);
        DigestInfo digestInfo = service.preSign(null, this.certificates, null, null, null);
        System.out.println(Base64.encodeBase64String(digestInfo.digestValue));
        return digestInfo.digestValue;
    }

    public boolean insertSignature(byte[] signature, String destFile, String srcFile, Date signedDate) {
        try {
            File outFile = new File(destFile);
            FileOutputStream os = new FileOutputStream(outFile);
            System.out.println("srcFile: " + srcFile);
            File file = new File(srcFile);
            URL fileURL = file.toURI().toURL();
            service = new OOXMLSignatureService(fileURL, signedDate);
            DigestInfo digestInfo = service.preSign(null, this.certificates, null, null, null);
            System.out.println(Base64.encodeBase64String(digestInfo.digestValue));
            service.postSign(signature, this.certificates);
            byte[] signedOOXMLData = service.getSignedOfficeOpenXMLDocumentData();
            os.write(signedOOXMLData);
            os.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] signHash(byte[] hash, PrivateKey pk) {
        byte[] signature = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            signature = cipher.doFinal(hash);
        } catch (Exception e) {
            System.out.println("Error" + e);
        }
        return signature;
    }
}
