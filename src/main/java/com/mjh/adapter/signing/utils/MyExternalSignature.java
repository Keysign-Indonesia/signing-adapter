package com.mjh.adapter.signing.utils;

import com.itextpdf.text.pdf.codec.Base64;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class MyExternalSignature implements ExternalSignature {
    Logger logger = LoggerFactory.getLogger(MyExternalSignature.class);

    private String profileName;
    private String hashAlgorithm;
    private String encryptionAlgorithm;
    private String signingUrl;
    private String jwToken;
    private String refToken;

    public MyExternalSignature(String profileName, String signingUrl, String hashAlgorithm, String jwToken, String refToken) {
        this.profileName = profileName;
        this.signingUrl = signingUrl;
        this.jwToken = jwToken;
        this.refToken = refToken;
        this.hashAlgorithm = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigests(hashAlgorithm));
        this.encryptionAlgorithm = "RSA";
    }

    @Override
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    @Override
    public byte[] sign(byte[] bytes) throws GeneralSecurityException {
        try {
            return Base64.decode(MyUtil.POSTHashRequestResponse(this.signingUrl, this.profileName, MyUtil.base64encode(bytes), jwToken, refToken));
        } catch (IOException ioException) {
            throw new GeneralSecurityException();
        }
    }
}
