package com.digitalsign.signbackend.verify;

import java.security.cert.X509Certificate;
import java.util.Date;

public class Verifier {
    boolean validity;
    Date validFrom;
    Date validTo;
    Object certificateStatus;
    Date signedDate;
    String signedCert;

    public boolean isValidity() {
        return validity;
    }

    public void setValidity(boolean validity) {
        this.validity = validity;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidTo() {
        return validTo;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    public Object getCertificateStatus() {
        return certificateStatus;
    }

    public void setCertificateStatus(Object certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    public Date getSignedDate() {
        return signedDate;
    }

    public void setSignedDate(Date signedDate) {
        this.signedDate = signedDate;
    }

    public String getSignedCert() {
        return signedCert;
    }

    public void setSignedCert(String signedCert) {
        this.signedCert = signedCert;
    }
}
