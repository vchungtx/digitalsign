/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.verify;

import com.google.gson.Gson;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Chungnv
 */
public class VerifyPDF {

    public Verifier verifySingleSignature(AcroFields fields, String name) {
        Verifier verifier = new Verifier();
        try {
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            verifier.setValidity(pkcs7.verify());
            Certificate[] certs = pkcs7.getSignCertificateChain();
            Calendar cal = pkcs7.getSignDate();
            X509Certificate signCert = (X509Certificate) certs[0];
            X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);
            verifier.setSignedDate(cal.getTime());
            verifier.setSignedCert(signCert.getSubjectDN().toString());
            verifier.setValidFrom(signCert.getNotBefore());
            verifier.setValidTo(signCert.getNotAfter());
            VerifyCert verifyCert = new VerifyCert();
            verifier.setCertificateStatus(verifyCert.checkRevocation(signCert, issuerCert));
        } catch (Exception exception) {
            exception.printStackTrace();
            verifier.setValidity(false);
        }
        return verifier;
    }

    public static void main(String[] args) throws Exception,
            GeneralSecurityException {

        LoggerFactory.getInstance().setLogger(new SysoLogger());

        BouncyCastleProvider provider = new BouncyCastleProvider();

        Security.addProvider(provider);

        VerifyPDF app = new VerifyPDF();

        List<Verifier> verifiers = app.verifySignatures("D:\\Projects\\CA\\sign-plugin\\Signed_Signed_ewallet_topo.pdf");
        System.out.println(new Gson().toJson(verifiers));

    }

    public List<Verifier> verifySignatures(String path) throws Exception, GeneralSecurityException {

        List response = new ArrayList();
        PdfReader reader = new PdfReader(path);

        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();

        for (String name : names) {
            response.add(verifySingleSignature(fields, name));
        }
        return response;

    }
}
