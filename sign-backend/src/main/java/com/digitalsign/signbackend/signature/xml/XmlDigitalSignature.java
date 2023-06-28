/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.signature.xml;

import org.apache.xml.security.utils.Constants;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.io.IOUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author chungnv14
 */
public class XmlDigitalSignature {

    public byte[] createDigest(String src, String tempFile, Certificate[] chain) throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document doc = dbFactory.newDocumentBuilder().parse(src);
        return createDigest(doc, tempFile, chain);
    }

    public byte[] createDigest(byte[] dataFile, String tempFile, Certificate[] chain) throws Exception {

        DocumentBuilderFactory dbFactory
                = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document doc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(dataFile));
        return createDigest(doc, tempFile, chain);
    }

    private byte[] createDigest(Document doc, String tempFile, Certificate[] chain) throws Exception {

        // prepare signature factory
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

        Node sigParent = doc.getDocumentElement();
        String referenceURI = ""; // Empty string means whole document
//        String referenceURI = "#_NODE_TO_SIGN";
        List transforms = Collections.singletonList(sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
        // Create a Reference to the enveloped document
        Reference ref = sigFactory.newReference(referenceURI,
                sigFactory.newDigestMethod(DigestMethod.SHA1, null),
                transforms, null, null);
        // Create the SignedInfo
        SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                sigFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(ref));

        // Create the SignedInfo.
        KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.addAll(Arrays.asList(chain));

        X509Data xd = keyInfoFactory.newX509Data(x509Content);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(xd));
        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = kpg.generateKeyPair();
        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), sigParent);

        // Create the XMLSignature (but don't sign it yet)
        List<XMLObject> objects = new LinkedList<XMLObject>();
        List<XMLStructure> objectContent = new LinkedList<XMLStructure>();
        String signatureId = "xmldsig-" + UUID.randomUUID().toString();
        addSignatureTime(sigFactory, doc, signatureId, objectContent);
        objects.add(sigFactory.newXMLObject(objectContent, null,
                null, null));

        XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo, objects, signatureId, null);

//        // Marshal, generate (and sign) the enveloped signature
        signature.sign(dsc);
        byte[] digest = IOUtils.toByteArray(signature.getSignedInfo().getCanonicalizedData());
        Transformer trans = TransformerFactory.newInstance().newTransformer();
        StreamResult res = new StreamResult(new FileOutputStream(tempFile));
        trans.transform(new DOMSource(doc), res);
        return digest;

    }

    public void insertSignature(String tempFile, String dest, byte[] extSignature) throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document doc = dbFactory.newDocumentBuilder().parse(tempFile);
        NodeList nl = doc.
                getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        Node signatureNode = nl.item(nl.getLength() - 1);
        NodeList childNodes = signatureNode.getChildNodes();
        Node signatureValue = null;
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node node = childNodes.item(i);
            if ("SignatureValue".equals(node.getNodeName())) {
                signatureValue = node;
                break;
            }
        }
        if (signatureValue != null) {
            String signatureXML = Base64.encodeBase64String(extSignature);
            signatureValue.setTextContent(signatureXML);
            Transformer trans = TransformerFactory.newInstance().
                    newTransformer();
            FileOutputStream os = new FileOutputStream(dest);
            StreamResult res = new StreamResult(os);
            trans.transform(new DOMSource(doc), res);
            os.close();
            (new File(tempFile)).delete();
        }
    }

    private void addSignatureTime(XMLSignatureFactory signatureFactory,
            Document document, String signatureId,
            List<XMLStructure> objectContent) {
        /*
             * SignatureTime
         */
        Element signatureTimeElement = document
                .createElementNS(
                        "http://schemas.openxmlformats.org/package/2006/digital-signature",
                        "mdssi:SignatureTime");
        signatureTimeElement
                .setAttributeNS(Constants.NamespaceSpecNS, "xmlns:mdssi",
                        "http://schemas.openxmlformats.org/package/2006/digital-signature");
        Element formatElement = document
                .createElementNS(
                        "http://schemas.openxmlformats.org/package/2006/digital-signature",
                        "mdssi:Format");
        formatElement.setTextContent("YYYY-MM-DDThh:mm:ssTZD");
        signatureTimeElement.appendChild(formatElement);
        Element valueElement = document
                .createElementNS(
                        "http://schemas.openxmlformats.org/package/2006/digital-signature",
                        "mdssi:Value");

        DateTimeFormatter fmt = ISODateTimeFormat.dateTimeNoMillis();

        String nowStr = fmt.print(new DateTime(Calendar.getInstance().getTime(), DateTimeZone.UTC));

        valueElement.setTextContent(nowStr);
        signatureTimeElement.appendChild(valueElement);

        List<XMLStructure> signatureTimeContent = new LinkedList<XMLStructure>();
        signatureTimeContent.add(new DOMStructure(signatureTimeElement));
        SignatureProperty signatureTimeSignatureProperty = signatureFactory
                .newSignatureProperty(signatureTimeContent, "#" + signatureId,
                        "idSignatureTime");
        List<SignatureProperty> signaturePropertyContent = new LinkedList<SignatureProperty>();
        signaturePropertyContent.add(signatureTimeSignatureProperty);
        SignatureProperties signatureProperties = signatureFactory
                .newSignatureProperties(signaturePropertyContent,
                        "id-signature-time-");
        objectContent.add(signatureProperties);
    }
}
