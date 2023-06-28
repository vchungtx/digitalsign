/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */
package com.digitalsign.signbackend.signature.ooxml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;


class OoxmlTemporaryDataStorage implements TemporaryDataStorage {
    /**
     * Out put stream of signed file
     */
    private ByteArrayOutputStream outputStream;
    /**
     * Mapping
     */
    private Map<String, Serializable> attributes;

    public OoxmlTemporaryDataStorage() {
        this.outputStream = new ByteArrayOutputStream();
        this.attributes = new HashMap<String, Serializable>();
    }

    @Override
    public InputStream getTempInputStream() {
        byte[] data = this.outputStream.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        return inputStream;
    }

    @Override
    public OutputStream getTempOutputStream() {
        return this.outputStream;
    }

    @Override
    public Serializable getAttribute(String attributeName) {
        return this.attributes.get(attributeName);
    }

    @Override
    public void setAttribute(String attributeName, Serializable attributeValue) {
        this.attributes.put(attributeName, attributeValue);
    }
}
