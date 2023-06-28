package com.digitalsign.signbackend.signature.pdf;

import com.digitalsign.signbackend.signature.plugin.SignPdfFile;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.io.RASInputStream;
import com.itextpdf.text.io.RandomAccessSource;
import com.itextpdf.text.io.RandomAccessSourceFactory;
import com.itextpdf.text.io.StreamUtil;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.ByteBuffer;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalBlankSignatureContainer;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ResourceUtils;

/**
 *
 * @author ChungNV14
 */
public class PdfDeferredSigning {

    private static final Logger logger = LoggerFactory.getLogger(PdfDeferredSigning.class);
    private static final String HASH_ALG = "SHA1";
    private static final String CRYPT_ALG = "RSA";

    public boolean insertSignature(String src, String dest, String fieldName,
            byte[] hash, byte[] extSignature, Certificate[] chain) {
        PdfReader reader = null;
        FileOutputStream os = null;
        try {
            BouncyCastleProvider providerBC = new BouncyCastleProvider();
            Security.addProvider(providerBC);
            reader = new PdfReader(src);
            os = new FileOutputStream(dest);
            AcroFields af = reader.getAcroFields();

            PdfDictionary v = af.getSignatureDictionary(fieldName);
            if (v == null) {
                logger.error("No field");
                return false;
            }
            if (!af.signatureCoversWholeDocument(fieldName)) {
                logger.error("Not the last signature");
                return false;
            }
            PdfArray b = v.getAsArray(PdfName.BYTERANGE);
            long[] gaps = b.asLongArray();
            if (b.size() != 4 || gaps[0] != 0) {
                logger.error("Single exclusion space supported");
                return false;
            }
            RandomAccessSource readerSource = reader.getSafeFile().createSourceView();
            String hashAlgorithm = HASH_ALG;
            BouncyCastleDigest digest = new BouncyCastleDigest();
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);
            sgn.setExternalDigest(extSignature, null, CRYPT_ALG);
            TSAClient tsaClient = null;
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = (X509Certificate) chain[i];
                String tsaUrl = CertificateUtil.getTSAURL(cert);
                if (tsaUrl != null) {
                    tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    break;
                }

            }
            byte[] signedContent = sgn.getEncodedPKCS7(hash, tsaClient, null, null, MakeSignature.CryptoStandard.CMS);
            int spaceAvailable = (int) (gaps[2] - gaps[1]) - 2;
            if ((spaceAvailable & 1) != 0) {
                logger.error("Gap is not a multiple of 2");
                return false;
            }
            spaceAvailable /= 2;
            if (spaceAvailable < signedContent.length) {
                logger.error("Not enough space");
                return false;
            }
            StreamUtil.CopyBytes(readerSource, 0, gaps[1] + 1, os);
            ByteBuffer bb = new ByteBuffer(spaceAvailable * 2);
            for (byte bi : signedContent) {
                bb.appendHex(bi);
            }
            int remain = (spaceAvailable - signedContent.length) * 2;
            for (int k = 0; k < remain; ++k) {
                bb.append((byte) 48);
            }
            bb.writeTo(os);
            StreamUtil.CopyBytes(readerSource, gaps[2] - 1, gaps[3] + 1, os);

            bb.close();
            return true;
        } catch (IOException | InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
            return false;
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ex) {
                    logger.error(ex.getMessage(), ex);
                }
            }
            if (reader != null) {
                reader.close();
            }
        }
    }

    public List<byte[]> createHash(String src, String tempFile, String fileName,
            Certificate[] chain) throws Exception {
        emptySignature(src, tempFile, fileName, chain);

        return preSign(tempFile, fileName, chain);
    }

    private List<byte[]> preSign(String src, String fieldName, Certificate[] chain) {
        PdfReader reader = null;
        try {

            List<byte[]> result = new ArrayList();
            reader = new PdfReader(src);
            AcroFields af = reader.getAcroFields();
            PdfDictionary v = af.getSignatureDictionary(fieldName);
            if (v == null) {
                logger.error("No field");
                return null;
            }
            PdfArray b = v.getAsArray(PdfName.BYTERANGE);
            long[] gaps = b.asLongArray();
            if (b.size() != 4 || gaps[0] != 0) {
                logger.error("Single exclusion space supported");
                return null;
            }
            RandomAccessSource readerSource = reader.getSafeFile().createSourceView();
            InputStream rg = new RASInputStream(new RandomAccessSourceFactory().createRanged(readerSource, gaps));

            BouncyCastleDigest digest = new BouncyCastleDigest();
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, HASH_ALG, null, digest, false);
            byte[] hash = DigestAlgorithms.digest(rg, digest.getMessageDigest(HASH_ALG));
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, MakeSignature.CryptoStandard.CMS);
            result.add(sh);
            result.add(hash);
            return result;
        } catch (IOException | InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        } catch (GeneralSecurityException ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

    public void emptySignature(String src, String dest, String fieldname, Certificate[] chain) throws IOException, DocumentException, GeneralSecurityException {

        PdfReader reader = new PdfReader(src);

        FileOutputStream os = new FileOutputStream(dest);

        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        //neu co sticky note thi chen anh chu ky, neu khong co thi tao form binh thuong
        //tim sticky note
        int numPages = reader.getNumberOfPages();
        PdfArray rect = null;
        int signPage = 0;
        for (int pageNum = 1; pageNum <= numPages; pageNum++) {
            PdfDictionary page = reader.getPageN(pageNum);
            PdfArray annotations = page.getAsArray(PdfName.ANNOTS);
            if (annotations == null) {
                continue;
            }
            for (int i = 0; i < annotations.size(); i++) {
                PdfDictionary annotation = annotations.getAsDict(i);

                PdfName subtype = annotation.getAsName(PdfName.SUBTYPE);
                if (PdfName.TEXT.equals(subtype)) {
                    // it's a text annotation
                    String contents = annotation.getAsString(PdfName.CONTENTS).toUnicodeString();
                    if ("SIGN".equals(contents)){
                        //lay toa do
                        rect = annotation.getAsArray(PdfName.RECT);
                        signPage = pageNum;
                    }

                }
            }
        }
        if (rect != null){
            //chen anh chu ky
            logger.info("rect:" + rect);
            Image image = Image.getInstance(ResourceUtils.getFile("classpath:condau.jpg").getPath());
            appearance.setSignatureGraphic(image);
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            int llx = rect.getAsNumber(0).intValue();
            int lly = rect.getAsNumber(1).intValue();
            appearance.setVisibleSignature(new Rectangle(llx, lly, llx + image.getWidth(), lly + image.getHeight()), signPage, fieldname);
        }else{
            //
            appearance.setVisibleSignature(new Rectangle(10, 10, 200, 50), 1, fieldname);
            Font font2 = new Font(BaseFont.createFont(ResourceUtils.getFile("classpath:times.ttf").getPath(), "Identity-H", false));
            font2.setColor(0xff, 0, 0);
            appearance.setLayer2Font(font2);
        }

        appearance.setCertificate(chain[0]);
        ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        MakeSignature.signExternalContainer(appearance, external, 8192);



    }

}
