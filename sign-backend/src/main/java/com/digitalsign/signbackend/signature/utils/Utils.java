package com.digitalsign.signbackend.signature.utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.apache.tomcat.util.codec.binary.Base64;

public class Utils {

    public static X509Certificate getX509Cert(String base64Cert) {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(base64Cert.getBytes())));
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X509Certificate[] getX509Chain(String base64Chain) {
        CertificateFactory cf = null;

        try {
            List<X509Certificate> listCert = new ArrayList<>();
            List<String> chainString = new Gson().fromJson(base64Chain, new TypeToken<List<String>>() {
            }.getType());
            cf = CertificateFactory.getInstance("X.509");
            for (String base64Cert : chainString) {
                listCert.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(base64Cert))));
            }
            return listCert.toArray(new X509Certificate[listCert.size()]);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

}
