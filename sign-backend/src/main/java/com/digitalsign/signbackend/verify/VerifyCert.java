/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.verify;


import com.digitalsign.signbackend.signature.utils.Utils;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.math.BigInteger;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.OperatorException;

import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.DEROctetString;
import com.itextpdf.text.pdf.PdfEncryption;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * @author Chungnv
 */
public class VerifyCert {

    private static final String base64Mic = "MIID1zCCAr+gAwIBAgIQG+Rzih8+wI9Hn6bPNcWYIjANBgkqhkiG9w0BAQUFADB+ MQswCQYDVQQGEwJWTjEzMDEGA1UEChMqTWluaXN0cnkgb2YgSW5mb3JtYXRpb24g YW5kIENvbW11bmljYXRpb25zMRswGQYDVQQLExJOYXRpb25hbCBDQSBDZW50ZXIx HTAbBgNVBAMTFE1JQyBOYXRpb25hbCBSb290IENBMB4XDTA4MDUxNjAxMTI0OVoX DTQwMDUxNjAxMjAzMlowfjELMAkGA1UEBhMCVk4xMzAxBgNVBAoTKk1pbmlzdHJ5 IG9mIEluZm9ybWF0aW9uIGFuZCBDb21tdW5pY2F0aW9uczEbMBkGA1UECxMSTmF0 aW9uYWwgQ0EgQ2VudGVyMR0wGwYDVQQDExRNSUMgTmF0aW9uYWwgUm9vdCBDQTCC ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKE/WVEO/jD/YduWeBSL20M8 Nr5hr9y1P2Ae0w0BQa34yYpCjsjtMoZHxf619+rWRDcQEsNICFFQuuVX6c41yY4c cwmFM0zhuzisjq23EwQuZoFXLcz7Gv0unIv9CUDwYBebcUVtfePbKtK7mt3rzF7k AN/VbDCFm71Xfy3UJNOA++AoUb6w1mEHzOWgR+eRbS+HWOi0rcGxRrPcWh04Cdn7 tSeYnl788fRI/+ihO/9QM9kmq7KZYp3Me8hSTZ5cQotvdH78lBPeCtLwtWr4lkxQ nOYhjsHllwFOzZ+wQBl8G1lvXDgZmjfa0YE5FjLvga2wIWsRl8LBCL1vI1wED9MC AwEAAaNRME8wCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE FM1iceRhvf497LJAYNOBdd06rGvGMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3 DQEBBQUAA4IBAQBMnc1+IyCAHCjP8PHJ3xHKsmlTo/JfDLNlnC9U4RxQKuBVF8QX vqiTUUaqhu0kZC9PE46wtBScfEO+LU5jUmzb1nAXWUdbolqzx5Z6tg31LQ3ZZDqv 0FQ60RNotvo4DgXr4Pww90ybX+LuZ3v4Yup0r3JUTNT6Xovs67gngSyYjvfKoFGW c8YXifn0U5c/V8PbVShJc09KNypnhMUTvsbJ7glHYr+osup85V8k2zu4dDWw4YWP ipdIjud4Z4nL5aQC7FtXobnHlrfB6eVdjpmmpyWaHbDO1jtrM/K+SeEt1oeBuXau p/zNs8Z2Mq9NUFJsLQ2yvddQ5dN1Y59dzQqZ";
    KeyStore ks;

    public VerifyCert() {
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("mic",
                    Utils.getX509Cert(base64Mic));
        } catch (Exception e) {
            System.out.println(e);
        }

    }

    public boolean verifyChain(Certificate[] chain) {
        try {
            int n = chain.length;
            for (int i = 0; i < n - 1; i++) {
                X509Certificate cert = (X509Certificate) chain[i];
                X509Certificate issuer = (X509Certificate) chain[i + 1];
                if (cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()) == false) {
                    return false;
                }
                cert.verify(issuer.getPublicKey());
                System.out.println("Verified: " + cert.getSubjectX500Principal());
            }
            X509Certificate last = (X509Certificate) chain[n - 1];
            // if self-signed, verify the final cert
            if (last.getIssuerX500Principal().equals(last.getSubjectX500Principal())) {
                last.verify(last.getPublicKey());
                System.out.println("Verified: " + last.getSubjectX500Principal());
            }
        } catch (Exception ex) {
            return false;
        }
        return true;

    }

    public void verifyCertInKeystore(Certificate[] chain, Calendar cal) {
        List errors = CertificateVerification.verifyCertificates(chain, ks, cal);
        if (errors.size() == 0) {
            System.out.println("Certificates verified against the KeyStore");
        } else {
            System.out.println(errors);
        }
    }

    /**
     * Gets an OCSP response online and returns it if the status is GOOD
     * (without further checking).
     *
     * @param signCert   the signing certificate
     * @param issuerCert the issuer certificate
     * @return an OCSP response
     */
    public String checkRevocation(X509Certificate signCert, X509Certificate issuerCert) {
        try {
            OcspClientBouncyCastle ocsp = new OcspClientBouncyCastle();
            BasicOCSPResp ocspResp = ocsp.getBasicOCSPResp(signCert, issuerCert, null);

            SingleResp[] resp = ocspResp.getResponses();
            for (int i = 0; i < resp.length; i++) {
                Object status = resp[i].getCertStatus();
                if (status instanceof RevokedStatus) {
                    System.out.println("The certificate has been revoked at " + ((RevokedStatus) status).getRevocationTime());
                    return "Revoked";

                } else if (status instanceof UnknownStatus) {
                    System.out.println("The certificate status is unknown");
                    return "Unknown";

                } else if (status == CertificateStatus.GOOD) {
                    System.out.println("The certificate status is good");
                    return "Good";
                }
            }
        } catch (Exception exception) {
//            exception.printStackTrace();

        }
        return "Unknown";
    }

    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, IOException,
            OperatorException, CertificateEncodingException {
        //Add provider BC
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generate the id for the certificate we are looking for
        CertificateID id = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert), serialNumber);

        // basic request generation with nonce
        OCSPReqBuilder gen = new OCSPReqBuilder();

        gen.addRequest(id);

        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(new DEROctetString(PdfEncryption.createDocumentId()).getEncoded()));
        gen.setRequestExtensions(new Extensions(new Extension[]{ext}));

        return gen.build();
    }

    public void showCertificateInfo(X509Certificate cert, Date signDate) {

        System.out.println("Issuer: " + cert.getIssuerDN());

        System.out.println("Subject: " + cert.getSubjectDN());

        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");

        System.out.println("Valid from: " + date_format.format(cert.getNotBefore()));

        System.out.println("Valid to: " + date_format.format(cert.getNotAfter()));

        try {

            cert.checkValidity(signDate);

            System.out
                    .println("The certificate was valid at the time of signing.");

        } catch (CertificateExpiredException e) {

            System.out
                    .println("The certificate was expired at the time of signing.");

        } catch (CertificateNotYetValidException e) {

            System.out
                    .println("The certificate wasn't valid yet at the time of signing.");

        }

        try {

            cert.checkValidity();

            System.out.println("The certificate is still valid.");

        } catch (CertificateExpiredException e) {

            System.out.println("The certificate has expired.");

        } catch (CertificateNotYetValidException e) {

            System.out.println("The certificate isn't valid yet.");

        }

    }

    public static void main(String[] args) throws Exception {
//        String revoke = "MIIEDzCCAvegAwIBAgIQVAT//rcDP7MW1nIgG3tGhTANBgkqhkiG9w0BAQUFADA6MQswCQYDVQQGEwJWTjEWMBQGA1UEChMNVmlldHRlbCBHcm91cDETMBEGA1UEAxMKVmlldHRlbC1DQTAeFw0xODA3MTYwODEyMTVaFw0yMDEwMDIwMjQyMjBaMIG5MSEwHwYJKoZIhvcNAQkBFhJiYWJpbmgxNUBnbWFpbC5jb20xHjAcBgoJkiaJk/IsZAEBDA5NU1Q6MDEwODM0MjI0OTFTMFEGA1UEAwxKQ8OUTkcgVFkgQ+G7lCBQSOG6pk4gQ8OUTkcgTkdI4buGIENBTyBWw4AgROG7ikNIIFbhu6QgUEjhuqZOIE3hu4BNIEZBQ0VORVQxEjAQBgNVBAcMCUjDgCBO4buYSTELMAkGA1UEBhMCVk4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK/rITEO8LZJewk84PE1+UoAm1GQgubkFqZPLRPcM42TwzAVGDr66Nbbzyy/ZXoKlsKbv7BTEGzW8jdNmr/Zzqppl4dULS8HqBH6I3Rnruk4sp/7mNIG+yM+RCEEDrXXbBv0ytJ4dgFMBLWwXJB8CYlkxqR+G4HAIFt1IZU31q1JAgMBAAGjggETMIIBDzA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnZpZXR0ZWwtY2Eudm4wHQYDVR0OBBYEFGfimAadlEpk6QTTobYIBpvPFKd7MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUCGDmHxsU2UiAC16nXHMlLCAN+dYweAYDVR0fBHEwbzBtoCugKYYnaHR0cDovL2NybC52aWV0dGVsLWNhLnZuL1ZpZXR0ZWwtQ0EuY3Jsoj6kPDA6MRMwEQYDVQQDDApWaWV0dGVsLUNBMRYwFAYDVQQKDA1WaWV0dGVsIEdyb3VwMQswCQYDVQQGEwJWTjAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQEFBQADggEBACpHsJAfy4C3xEc3SedpiTa2ONlLJRmNRnX90CMxdFAC72cF4KWrIodfKV0neZ3W/OA12KPwxJ1PcINMzrqM3KtXHWuUNma+YeH7RGL1l/WtaFAXYNOPOlKaN41IdE66DTRd9yDls0AEqzj1D5R4dC5wejava2RqThiKrG+Qok4m5t+Yp6Z1OvmRo8RtJkMyew8OWcafgOddbfSTgGaVxSjlrkmvgtUHYIlycghE4BI2EokSPlI8md2WksNQHBP37j7lu+oR1a3WyxGQKHANSZPUe8BuXAFBTlTr/7C8bRln6izfH0Mpvpx/fEJzEdsNlUeoCfFIC6t6jbizq+8GT4Q=";
//        String issue = "MIIEKDCCAxCgAwIBAgIKYQ4N5gAAAAAAETANBgkqhkiG9w0BAQUFADB+MQswCQYDVQQGEwJWTjEzMDEGA1UEChMqTWluaXN0cnkgb2YgSW5mb3JtYXRpb24gYW5kIENvbW11bmljYXRpb25zMRswGQYDVQQLExJOYXRpb25hbCBDQSBDZW50ZXIxHTAbBgNVBAMTFE1JQyBOYXRpb25hbCBSb290IENBMB4XDTE1MTAwMjAyMzIyMFoXDTIwMTAwMjAyNDIyMFowOjELMAkGA1UEBhMCVk4xFjAUBgNVBAoTDVZpZXR0ZWwgR3JvdXAxEzARBgNVBAMTClZpZXR0ZWwtQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLdiGZcPhwSm67IiLUWELaaol8kHF+qHPmEdcG0VDKf0FtpSWiE/t6NPzqqmoF4gbIrue1/TzUs7ZeAj28o6Lb2BllA/zB6YFrXfppD4jKqHMO139970MeTbDrhHTbVugX4t2QHS+B/p8+8lszJpuduBrnZ/LWxbhnjeQRr21g89nh/W5q1VbIvZnq4ci5m0aDiJ8arhK2CKpvNDWWQ5E0L7NTVoot8niv6/Wjz19yvUCYOKHYsq97y7eBaSYmpgJosD1VtnXqLG7x4POdb6Q073eWXQB0Sj1qJPrXtOqWsnnmzbbKMrnjsoE4gg9B6qLyQS4kRMp0RrUV0z041aUFAgMBAAGjgeswgegwCwYDVR0PBAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFAhg5h8bFNlIgAtep1xzJSwgDfnWMB8GA1UdIwQYMBaAFM1iceRhvf497LJAYNOBdd06rGvGMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9wdWJsaWMucm9vdGNhLmdvdi52bi9jcmwvbWljbnJjYS5jcmwwRwYIKwYBBQUHAQEEOzA5MDcGCCsGAQUFBzAChitodHRwOi8vcHVibGljLnJvb3RjYS5nb3Yudm4vY3J0L21pY25yY2EuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQCHtdHJXudu6HjO0571g9RmCP4b/vhK2vHNihDhWYQFuFqBymCota0kMW871sFFSlbd8xD0OWlFGUIkuMCz48WYXEOeXkju1fXYoTnzm5K4L3DV7jQa2H3wQ3VMjP4mgwPHjgciMmPkaBAR/hYyfY77I4NrB3V1KVNsznYbzbFtBO2VV77s3Jt9elzQw21bPDoXaUpfxIde+bLwPxzaEpe7KJhViBccJlAlI7pireTvgLQCBzepJJRerfp+GHj4Z6T58q+e3a9YhyZdtAHVisWYQ4mY113K1V7Z4D7gisjbxExF4UyrX5G4W0h0gXAR5UVOstv5czQyDraTmUTYtx5J";
        String revoke = "MIIFpDCCBIygAwIBAgIQDZzrUH6oEudDYieQv46XXTANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSMwIQYDVQQDExpEaWdpQ2VydCBCYWx0aW1vcmUgQ0EtMiBHMjAeFw0xNzA0MjYwMDAwMDBaFw0yMDA0MjkxMjAwMDBaMGkxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIEwRVdGFoMQ0wCwYDVQQHEwRMZWhpMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEjMCEGA1UEAwwaKi5jaGFpbi1kZW1vcy5kaWdpY2VydC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6XjqcBDnQcS22vPQpQR4XjQbkj5bY2eK0QJbpcF+ceNkcnnsa/IVhSX9x+WPOVg4dWtpdVsdMCITZOM81jEmp9rllhx/kPRjJb2hSNHjfKAedKZxXPxU6gKBc/Rcrbwi02OF/Q2QpczMwohsDh32FtOwWf9eXOQrpSpkXr5n0wEXQ8A+lgK2h5FoRwcG1VqYBKUsLTZ+1Fq8bU7EvNUVPQJBOCU50tyZQ5buI/ZxCXQrt8dfvINhv0NWJlNsPwtQ2RF70TNS4ZZKg/1nWCMErJsbphDqnN3PRt6IbWgSvXMSgP3DVMAB0tAI9c4SC4EdIdBN5gvqwTPQNmOoQPMdtAgMBAAGjggJLMIICRzAfBgNVHSMEGDAWgBTAErIodGhGZ+lwJXQaAEVbBn1cRDAdBgNVHQ4EFgQUJa+cY9D3AX8v2w3RL9S5qIIW4ecwewYDVR0RBHQwcoIaKi5jaGFpbi1kZW1vcy5kaWdpY2VydC5jb22CGGNoYWluLWRlbW9zLmRpZ2ljZXJ0LmNvbYI6YmFsdGltb3JlLWN5YmVydHJ1c3Qtcm9vdC1yZXZva2VkLmNoYWluLWRlbW9zLmRpZ2ljZXJ0LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRCYWx0aW1vcmVDQS0yRzIuY3JsMDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRCYWx0aW1vcmVDQS0yRzIuY3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAEBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQICMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRCYWx0aW1vcmVDQS0yRzIuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAG0m5ibaFdhRW+SRKj4AVBlutPEEl96E5HqM2g8L15wqPTEydaur520+Y1DPrjNih+j2lI//kp+rd0EbGowLhQRPi0YPbAbDH2SE/Ff/bSawNwljJiywcIos+4lsVAUnoC0akATMt5OQIw0JiQwhGu3x7tbN+qnJw+Z8TNgCUuFrtvavLVVzbtrQH8hBNx4O678lW5BaOptuMGKywIF/9q6mF3GQZJikieolDQtykxUvobdODXTYKhDux6XWvX6Ry0CEJ7NvqBdflJCXuNnXH26LzFfm4NNq4YEr+K6CZTCGuaROO/7mlumV0arZ4FwMmdclMli6br15grbM8Uk1z9g=";
        String issue = "MIIFMTCCBBmgAwIBAgIQVAEBBHBaECcrI/rg5a8qUjANBgkqhkiG9w0BAQUFADBuMQswCQYDVQQGEwJWTjEYMBYGA1UEChMPRlBUIENvcnBvcmF0aW9uMR8wHQYDVQQLExZGUFQgSW5mb3JtYXRpb24gU3lzdGVtMSQwIgYDVQQDExtGUFQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTkwMjIyMTQ1NjMzWhcNMjAxMDIxMDM0NDU3WjB+MR0wGwYDVQQDDBRU4buVbmcgIGPhu6VjIFRodeG6vzEXMBUGA1UECgwOTVNUOjAxMDAyMzEyMjYxNzA1BgNVBAcMLlPDtCAgMTIzIEzDsiDEkMO6YyAsIEhhaSBCw6AgVHLGsG5nLCBIw6AgTuG7mWkxCzAJBgNVBAYTAlZOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKg/XBu1Cex/Q36/m9/9YISS69FpfFsZX9NhPwwjOJG6t7SUqZU5C82TMc2VzcF8w0V6SzvA3evBj52TqFQG06jhVpfoilFaJaav3OnM80yDnmJnyEVVAA9iSIDbpxAm3dDP945x1hOYxTId7gMYqyL729qEAbUgpuFrdFwKHYsQp5TnBq0zZG7nZaQiHbTIUVaCG/fFtdM2IhVFG5+tzeFF6FrzHyd1Du22AyoD7PrkPsQsc3cEPLjZHtEulQTxiz36+WcVh6OQWZLo+0dBDXwVI9Tb2c/zaHbK7AoQZ2O2iNrmnsKO0RlEn0s+5Slfe9jEA0kTjXqWom6etqKYhQIDAQABo4IBuTCCAbUwgZ4GCCsGAQUFBwEBBIGRMIGOMDcGCCsGAQUFBzAChitodHRwOi8vcHVibGljLnJvb3RjYS5nb3Yudm4vY3J0L21pY25yY2EuY3J0MC8GCCsGAQUFBzAChiNodHRwOi8vd3d3LmZpcy5jb20udm4vY3J0L2ZwdGNhLmNydDAiBggrBgEFBQcwAYYWaHR0cDovL29jc3AuZmlzLmNvbS52bjAdBgNVHQ4EFgQUM2zXoZGSW2pAyzyY2kUPQRfwYQAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSz3nGSHEUdyZtP9xeVU86iTetZMjAZBgNVHSAEEjAQMA4GDCsGAQQBge0DAQQBBjAtBgNVHR8BAf8EIzAhMB+gHaAbhhlodHRwOi8vY3JsLmZpcy5jb20udm4vZ2V0MA4GA1UdDwEB/wQEAwIB/jBqBgNVHSUBAf8EYDBeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAw8GCCsGAQUFBwMQBggrBgEFBQcDEQYKKwYBBAGCNxQCAgYKKwYBBAGCNwoDDDANBgkqhkiG9w0BAQUFAAOCAQEAPlnTg4d9rdl/FaKEFPXAiR+Jwijy8xckQJ17bzxaOkDZxvFSMirzHC3OT5Hd69QyPTK4L9QSNEsgELJIsvDVKVthqJsco+nwqrqM2v85prMHrOonbGIxPWnW1xqYj9Zprj/QM9chgAZFT3v2fYejiA5kaevAQny33/mJrG62uNKlZ50aGB2Y0ew8LsMucHLau56OXn1armm0C0Egqtv8thTFXvUuM+uo7m2A+w7jjG4glreG7x//9rDONEwadkamF8z65ysQfkYkKLt2C9/x0ji3SpCml0xG+IWZBFYh8VFrUEShekVDVtCNUlaxrgftmjg6AK/tgHfb1GqUVvPvOw==";
        X509Certificate inner = Utils.getX509Cert(revoke);
        X509Certificate ca = Utils.getX509Cert(issue);
        getOcspResponse(inner, ca);
        System.out.println(getOcspUrl(ca));
    }

    /**
     * Gets an OCSP response online and returns it if the status is GOOD
     * (without further checking).
     *
     * @param signCert   the signing certificate
     * @param issuerCert the issuer certificate
     * @return an OCSP response
     */
    public static BasicOCSPResp getOcspResponse(X509Certificate signCert, X509Certificate issuerCert) {
        if (signCert == null && issuerCert == null) {
            return null;
        }
        OcspClientBouncyCastle ocsp = new OcspClientBouncyCastle();
        BasicOCSPResp ocspResp = ocsp.getBasicOCSPResp(signCert, issuerCert, null);
        if (ocspResp == null) {
            return null;
        }
        SingleResp[] resp = ocspResp.getResponses();
        for (int i = 0; i < resp.length; i++) {
            Object status = resp[i].getCertStatus();
            if (status instanceof RevokedStatus) {
                return ocspResp;
            }
        }
        return null;
    }

    private static String getOcspUrl(X509Certificate certificate) throws Exception {
        byte[] octetBytes = certificate
                .getExtensionValue(X509Extension.authorityInfoAccess.getId());

        DLSequence dlSequence = null;
        ASN1Encodable asn1Encodable = null;

        try {
            ASN1Primitive fromExtensionValue = X509ExtensionUtil
                    .fromExtensionValue(octetBytes);
            if (!(fromExtensionValue instanceof DLSequence)) {
                return null;
            }
            dlSequence = (DLSequence) fromExtensionValue;
            for (int i = 0; i < dlSequence.size(); i++) {
                asn1Encodable = dlSequence.getObjectAt(i);
                if (asn1Encodable instanceof DLSequence) {
                    break;
                }
            }
            if (!(asn1Encodable instanceof DLSequence)) {
                return null;
            }
            dlSequence = (DLSequence) asn1Encodable;
            for (int i = 0; i < dlSequence.size(); i++) {
                asn1Encodable = dlSequence.getObjectAt(i);
                if (asn1Encodable instanceof DERTaggedObject) {
                    break;
                }
            }
            if (!(asn1Encodable instanceof DERTaggedObject)) {
                return null;
            }
            DERTaggedObject derTaggedObject = (DERTaggedObject) asn1Encodable;
            byte[] encoded = derTaggedObject.getEncoded();
            if (derTaggedObject.getTagNo() == 6) {
                int len = encoded[1];
                return new String(encoded, 2, len);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
