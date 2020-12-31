package com.mjh.adapter.signing.utils;

import com.itextpdf.text.pdf.codec.Base64;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyOldExternalSignature implements ExternalSignature {
    Logger logger = LoggerFactory.getLogger(MyOldExternalSignature.class);

    private String profileName;
    private String hashAlgorithm;
    private String encryptionAlgorithm;
    private String signingUrl;
    private String jwToken;
    private String refToken;
    private String keyId;

    public MyOldExternalSignature(String profileName, String signingUrl, String hashAlgorithm, String jwToken, String refToken, String keyId) {
        logger.debug("Create new external signing");
        this.profileName = profileName;
        this.signingUrl = signingUrl;
        this.jwToken = jwToken;
        this.refToken = refToken;
        this.hashAlgorithm = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigests(hashAlgorithm));
        logger.debug("External signing hashAlgorithm : "+ this.hashAlgorithm);
        this.encryptionAlgorithm = "RSA";
        this.keyId = keyId;
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
    public byte[] sign(byte[] bytes) throws SignAdapterException {
        logger.debug("Processing External Sign method process");
        try {
            return Base64.decode(MyUtil.POSTHashRequestResponse(this.signingUrl, this.profileName, MyUtil.utilBase64encode(bytes), jwToken, refToken, keyId));
        } catch (SignAdapterException sae) {
            throw sae;
        } catch (Exception ex) {
            throw new SignAdapterException("Error while signing ["+ex.getMessage()+"]", ex.getCause(), ConstantID.errCodeExternalHashSigning);
        }
    }
}
