/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.verify;

import be.fedict.eid.applet.service.signer.ooxml.OOXMLProvider;
import com.digitalsign.signbackend.signature.ooxml.KeyInfoKeySelector;
import com.google.gson.Gson;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;

import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author Chungnv
 */
public class VerifyXML {

    public List<Verifier> verifySignatures(String filePath) {

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(
                    new FileInputStream(filePath));
            return verifySignatures(doc);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
       return null;
    }

    public List<Verifier> verifySignatures(Document doc) {
        List response = new ArrayList();
        try {
            NodeList nl = doc.
                    getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            while (nl.getLength() > 0) {
                Node signatureNode = nl.item(nl.getLength() - 1);
                response.add(verifySingleSignature(signatureNode));
                Node parentNode = signatureNode.getParentNode();
                parentNode.removeChild(signatureNode);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return response;
    }

    private Verifier verifySingleSignature(Node signatureNode)  {
        Verifier verifier = new Verifier();
        try {
            Date signedDate = parserTime(getTime(signatureNode));
            VerifyCert verifyCert = new VerifyCert();
            KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext valContext = new DOMValidateContext(keySelector,
                    signatureNode);

            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            verifier.setValidity(signature.validate(valContext));
            Certificate[] certs = keySelector.getCertificateChain();
            verifyCert.verifyChain(certs);
            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = (X509Certificate) certs[i];
                System.out.println("=== Certificate " + i + " ===");
                verifyCert.showCertificateInfo(cert, signedDate);
            }

            X509Certificate signCert = (X509Certificate) certs[0];
            X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);
            verifier.setSignedDate(signedDate);
            verifier.setSignedCert(signCert.getSubjectDN().toString());
            verifier.setValidFrom(signCert.getNotBefore());
            verifier.setValidTo(signCert.getNotAfter());
            verifier.setCertificateStatus(verifyCert.checkRevocation(signCert, issuerCert));

        }catch (Exception ex){
            verifier.setValidity(false);
        }
        return verifier;

    }

    private String getTime(Node node) {
        Node n0 = node.getChildNodes().item(3);

        Node n = n0.getChildNodes().item(0);

        Node n1 = n.getChildNodes().item(0);

        Node n2 = n1.getChildNodes().item(0);

        Node n3 = n2.getChildNodes().item(1);
        return n3.getTextContent();
    }

    private Date parserTime(String time) {
        DateTimeFormatter dtf = ISODateTimeFormat.dateTimeNoMillis();
        DateTime dt = dtf.parseDateTime(time);
        Date date = dt.toDate();
        return date;
    }

    public static void main(String[] args) throws Exception,
            GeneralSecurityException {

        LoggerFactory.getInstance().setLogger(new SysoLogger());

        BouncyCastleProvider provider = new BouncyCastleProvider();

        Security.addProvider(provider);

        VerifyXML app = new VerifyXML();
        OOXMLProvider.install();
        List<Verifier> verifiers = app.verifySignatures("D:\\Projects\\CA\\sign-plugin\\Signed_HAN-8264832005000-02_QTT-TNCN-012021122021-L00.xml");
        System.out.println(new Gson().toJson(verifiers));
    }
}
