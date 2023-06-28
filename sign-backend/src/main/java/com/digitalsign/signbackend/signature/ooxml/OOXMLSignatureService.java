
package com.digitalsign.signbackend.signature.ooxml;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.ooxml.AbstractOOXMLSignatureService;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Date;


class OOXMLSignatureService extends AbstractOOXMLSignatureService {

    /**
     * File url
     */
    private final URL ooxmlUrl;
    /**
     * data storage
     */
    private final OoxmlTemporaryDataStorage temporaryDataStorage;
    /**
     * signed output stream
     */
    private final ByteArrayOutputStream signedOOXMLOutputStream;
    /**
     * signing comment
     */

    public OOXMLSignatureService(URL ooxmlUrl, Date signedDate) {
        super(DigestAlgo.SHA1, signedDate);
        this.temporaryDataStorage = new OoxmlTemporaryDataStorage();
        this.signedOOXMLOutputStream = new ByteArrayOutputStream();
        this.ooxmlUrl = ooxmlUrl;

    }


    @Override
    protected URL getOfficeOpenXMLDocumentURL() {
        return this.ooxmlUrl;
    }

    @Override
    protected OutputStream getSignedOfficeOpenXMLDocumentOutputStream() {
        return this.signedOOXMLOutputStream;
    }

    public byte[] getSignedOfficeOpenXMLDocumentData() {
        return this.signedOOXMLOutputStream.toByteArray();
    }

    @Override
    protected OoxmlTemporaryDataStorage getTemporaryDataStorage() {
        return this.temporaryDataStorage;
    }


}
