/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.verify;

import be.fedict.eid.applet.service.signer.facets.XAdESXLSignatureFacet;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.ObjectFactory;
import be.fedict.eid.applet.service.signer.ooxml.OOXMLProvider;
import be.fedict.eid.applet.service.signer.ooxml.OOXMLSignatureVerifier;
import be.fedict.eid.applet.service.signer.ooxml.OOXMLURIDereferencer;
import com.digitalsign.signbackend.signature.ooxml.KeyInfoKeySelector;
import com.digitalsign.signbackend.signature.utils.Utils;
import com.google.gson.Gson;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.commons.io.IOUtils;

import static org.bouncycastle.crypto.tls.HandshakeType.certificate;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author Chungnv
 */
public class VerifyOOXML {

    public static final String DIGITAL_SIGNATURE_ORIGIN_REL_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
    public static final String DIGITAL_SIGNATURE_REL_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";
    private final Unmarshaller relationshipsUnmarshaller;

    public VerifyOOXML() {
        try {
            JAXBContext relationshipsJAXBContext = JAXBContext.newInstance(new Class[]{ObjectFactory.class});

            this.relationshipsUnmarshaller = relationshipsJAXBContext.createUnmarshaller();
        } catch (JAXBException e) {
            throw new RuntimeException("JAXB error: " + e.getMessage(), e);
        }
    }

    private static boolean initialed = false;

    public static void initial() {
        if (!initialed) {
            OOXMLProvider.install();
            initialed = true;
        }
    }

    public static boolean isOOXML(URL url)
            throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(url.openStream());
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if ("[Content_Types].xml".equals(zipEntry.getName())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isOOXML(String name)
            throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(name));
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if ("[Content_Types].xml".equals(zipEntry.getName())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isOOXML(InputStream is)
            throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(is);
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if ("[Content_Types].xml".equals(zipEntry.getName())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isOOXML(byte[] file)
            throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(file));
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if ("[Content_Types].xml".equals(zipEntry.getName())) {
                return true;
            }
        }
        return false;
    }

    public List<Verifier> verify(URL url) {
        List response = new ArrayList();
        try {
            OOXMLSignatureVerifier verifier = new OOXMLSignatureVerifier();
            byte[] document = IOUtils.toByteArray(url.openStream());
            List<String> signatureResourceNames = verifier.getSignatureResourceNames(document);
            OOXMLURIDereferencer dereferencer = new OOXMLURIDereferencer(url);
            for (String signatureResourceName : signatureResourceNames) {
                Document signatureDocument = verifier.getSignatureDocument(url, signatureResourceName);
                response.add(verifySingleSignature(dereferencer, signatureDocument));
            }
        }catch (Exception exception){
            exception.printStackTrace();
        }
        return response;
    }

    private Verifier verifySingleSignature(OOXMLURIDereferencer dereferencer, Document signatureDocument) {
        Verifier verifier = new Verifier();
        try {
            NodeList signatureNodeList = signatureDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            if (0 == signatureNodeList.getLength()) {
                //no signature
                verifier.setValidity(false);
                return verifier;
            }
            Node signatureNode = signatureNodeList.item(0);
            Element signedPropertiesElement = (Element) ((Element) signatureNode)
                    .getElementsByTagNameNS(XAdESXLSignatureFacet.XADES_NAMESPACE, "SignedProperties").item(0);
            if (null != signedPropertiesElement) {
                signedPropertiesElement.setIdAttribute("Id", true);
            }

            KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
            DOMValidateContext domValidateContext = new DOMValidateContext(keySelector, signatureNode);

            domValidateContext.setProperty("org.jcp.xml.dsig.validateManifests", Boolean.TRUE);

            domValidateContext.setURIDereferencer(dereferencer);

            XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();

            XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
            verifier.setValidity(xmlSignature.validate(domValidateContext));
            Date signedDate = parserTime(getTime(signatureNode));
            List<X509Certificate> listCert = new LinkedList();
            listCert.add(keySelector.getCertificate());
            NodeList encapsulatedX509CertificateNodeList = signatureDocument.getElementsByTagNameNS(XAdESXLSignatureFacet.XADES_NAMESPACE, "EncapsulatedX509Certificate");
            for (int i = 0; i < encapsulatedX509CertificateNodeList.getLength(); i++) {
                X509Certificate cert = Utils.getX509Cert(encapsulatedX509CertificateNodeList.item(i).getTextContent());
                listCert.add(cert);
            }
            Certificate[] certs = listCert.toArray(new Certificate[listCert.size()]);
            X509Certificate signCert = (X509Certificate) certs[0];
            X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);
            verifier.setSignedDate(signedDate);
            verifier.setSignedCert(signCert.getSubjectDN().toString());
            verifier.setValidFrom(signCert.getNotBefore());
            verifier.setValidTo(signCert.getNotAfter());
            VerifyCert verifyCert = new VerifyCert();
            verifier.setCertificateStatus(verifyCert.checkRevocation(signCert, issuerCert));
        } catch (Exception exception) {
            verifier.setValidity(false);
        }
        return verifier;


    }

    private String getTime(Node node) {
        Node n0 = node.getChildNodes().item(3);

        Node n = n0.getChildNodes().item(1);

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

    public static void main(String[] args) throws Exception {

        LoggerFactory.getInstance().setLogger(new SysoLogger());

        initial();
        VerifyOOXML app = new VerifyOOXML();

//        app.verify(new File("F:\\Project\\Others\\trunk\\SignPlugin\\DemoSignFile\\Signed_FacePlus_admin.docx").toURI().toURL());
        List<Verifier> verifiers = app.verify(new File("D:\\Projects\\CA\\sign-plugin\\Signed_Quản lý client.docx").toURI().toURL());
        System.out.println(new Gson().toJson(verifiers));

    }
}
