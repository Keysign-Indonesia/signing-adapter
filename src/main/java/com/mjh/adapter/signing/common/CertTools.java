package com.mjh.adapter.signing.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CertTools {

    private static final Logger log = LoggerFactory.getLogger(CertTools.class);

    /**
     * inhibits creation of new CertTools
     */
    protected CertTools() {
    }

    /**
     * Return the CRL distribution point URL form a certificate.
     */
    public static URL getCrlDistributionPoint(Certificate certificate)
            throws CertificateParsingException {
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) certificate;
            try {
                ASN1Object obj = getExtensionValue(x509cert, Extension.cRLDistributionPoints);
                if (obj == null) {
                    return null;
                }
                ASN1Sequence distributionPoints = (ASN1Sequence) obj;
                for (int i = 0; i < distributionPoints.size(); i++) {
                    ASN1Sequence distrPoint = (ASN1Sequence) distributionPoints.getObjectAt(i);
                    for (int j = 0; j < distrPoint.size(); j++) {
                        ASN1TaggedObject tagged = (ASN1TaggedObject) distrPoint.getObjectAt(j);
                        if (tagged.getTagNo() == 0) {
                            String url
                                    = getUriFromGeneralNames(tagged.getObject());
                            if (url != null) {
                                return new URL(url);
                            }
                        }
                    }
                }
            }
            catch (Exception e) {
                log.error("Error parsing CrlDistributionPoint", e);
                throw new CertificateParsingException(e.toString(), e);
            }
        }
        return null;
    }

    private static String getUriFromGeneralNames(ASN1Object names) {
        ASN1Sequence namesSequence = ASN1Sequence.getInstance((ASN1TaggedObject)names, false);
        if (namesSequence.size() == 0) {
            return null;
        }
        DERTaggedObject taggedObject
                = (DERTaggedObject)namesSequence.getObjectAt(0);
        if (taggedObject.getTagNo() != 6) { // uniformResourceIdentifier  [6]  IA5String,
            return null;
        }
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
    } //getStringFromGeneralNames

    /**
     * Return an Extension DERObject from a certificate
     */
    protected static ASN1Object getExtensionValue(X509Certificate cert, ASN1ObjectIdentifier oid)
            throws IOException {
        if (cert == null) {
            return null;
        }
        byte[] bytes = cert.getExtensionValue(oid.getId());
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    } //getExtensionValue

}
