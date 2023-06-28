/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.digitalsign.signbackend.signature.plugin;

import java.io.Serializable;
import java.security.cert.Certificate;

/**
 *
 * @author chungnv14
 */
public abstract interface IFileSigner extends Serializable {
    abstract public String createHash(String filePath, Certificate[] chain) throws Exception;
    abstract public boolean insertSignature(String extSig, String destFile, Certificate[] chain) throws Exception;
}
