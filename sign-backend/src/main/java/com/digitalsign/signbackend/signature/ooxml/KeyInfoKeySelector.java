package com.digitalsign.signbackend.signature.ooxml;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class KeyInfoKeySelector extends KeySelector implements KeySelectorResult {

        /**
         * signer certificate
         */
	private X509Certificate certificate;
        /**
         * signer certificate chain
         */
        private Certificate[] certificates;

	@SuppressWarnings("unchecked")
	@Override
	public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
			AlgorithmMethod method, XMLCryptoContext context)
			throws KeySelectorException {

		if (null == keyInfo) {
			throw new KeySelectorException("no ds:KeyInfo present");
		}
		List<XMLStructure> keyInfoContent = keyInfo.getContent();
		this.certificate = null;
                this.certificates = null;
		for (XMLStructure keyInfoStructure : keyInfoContent) {
			if (false == (keyInfoStructure instanceof X509Data)) {
				continue;
			}
			X509Data x509Data = (X509Data) keyInfoStructure;
			List<Object> x509DataList = x509Data.getContent();
                        certificates = new Certificate[x509DataList.size()];
                        int i = 0;
			for (Object x509DataObject : x509DataList) {
				if (false == (x509DataObject instanceof X509Certificate)) {
					throw new KeySelectorException("not supported certificate");
				}
                                certificates[i] = (Certificate) x509DataObject;
                                        i++;
				X509Certificate certificate = (X509Certificate) x509DataObject;

				if (null == this.certificate) {
					/*
					 * The first certificate is presumably the signer.
					 */
					this.certificate = certificate;

				}
			}
			if (null != this.certificate) {
				return this;
			}
		}
		throw new KeySelectorException("No key found!");
	}

	public Key getKey() {
		return this.certificate.getPublicKey();
	}

	/**
	 * Gives back the X509 certificate used during the last signature
	 * verification operation.
	 * @return X509 certificate
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

        public Certificate[] getCertificateChain() {
		return this.certificates;
	}
}
