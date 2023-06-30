package com.mjh.adapter.signing.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.BadPdfFormatException;
import com.itextpdf.text.pdf.PdfImportedPage;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfSmartCopy;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.EncryptionAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import com.mjh.adapter.signing.model.DocFileSigningRequest;
import com.mjh.adapter.signing.model.DocFileSigningResponse;
import com.mjh.adapter.signing.utils.MyExternalSignature;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("signingadapterservices")
@RequestMapping({"/adapter/pdfsigning/rest"})
@Tag(name="Signing Adapter Service", description="Operations to signing document")
public class SigningAdapterService {
    @Value("${MJ_HASH_URL}")
    private String hashUrl;

    @Value("${MJ_CERTCHAIN_URL}")
    private String certChainUrl;

    @Value("${SIGNER_PROFILE_NAME}")
    private String defaultSignerProfileName;

    @Value("${CRL_URL}")
    private String crlURL;

    @Value("${TSA_URL}")
    private String tsaURL;

    @Value("${tsa.service-user}")
    private String tsaUsername;

    @Value("${tsa.service-pass}")
    private String tsaPassword;

    @Value("${apg.keyId}")
    private String strKeyId;
    @Value("${apg.systemId}")
    private String strSystemId;

    @Autowired
    private RTSigningService rtSigningService;

    Logger logger = LoggerFactory.getLogger(SigningAdapterService.class);

    @PostMapping({"/docSigningZ"})
    @Operation(summary = "docSigningZ", description = "Signing Document File Rest Service")
    public ResponseEntity<DocFileSigningResponse> docSigningZ(@RequestBody DocFileSigningRequest signingRequest) throws Exception {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        DocFileSigningResponse docFileSigningResponse;
        String serviceName = "docSigningZ";
        long startTime = System.currentTimeMillis();
        String trxId = UUID.randomUUID().toString();
        ObjectMapper mapper = new ObjectMapper();
        try {
            logger.info(serviceStart(trxId, serviceName));
            logger.debug("[{}] request:: \n{}", trxId, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signingRequest));
        } catch (Exception ignored) {}
        try {
            if (signingRequest != null && "ALLOK".equals(signingRequest.checkInput())) {
                checkAndWarningSpesificEmptyParam(signingRequest);
                MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
                String shaChecksum = getFileChecksum(sha256Digest, new File(signingRequest.getSrc()));
                String newSrc = validateOrUpgrade(signingRequest.getSrc(), signingRequest.getDest(), signingRequest.getDocpass());
                if (!signingRequest.getSrc().equals(newSrc))
                    signingRequest.setSrc(newSrc);
                String signerProfileName = signingRequest.getProfileName();
                if (signerProfileName != null && !"".equals(signerProfileName.trim())) {
//                    List<Certificate> certs = MyUtil.getSignerCertChainRequestResponse(this.certChainUrl, signerProfileName
//                    , signingRequest.getJwToken(), signingRequest.getRefToken(), this.strKeyId);
                    List<Certificate> certs = rtSigningService.getSignerCertChainRequestResponse(this.certChainUrl, signerProfileName
                            , signingRequest.getJwToken(), signingRequest.getRefToken(), strSystemId, strKeyId, trxId);
                    Certificate[] chain = certs.<Certificate>toArray(new Certificate[certs.size()]);
                    this.logger.debug("Finish getting certificate chain");
                    TSAClient tsaClient = null;
                    this.logger.debug("Try setup TSAClient");
                    if (this.tsaURL != null && !"".equals(this.tsaURL.trim())) {
                        if (this.tsaUsername != null && !"".equals(this.tsaUsername.trim()) && !"yourusername".equals(this.tsaUsername.trim()) &&
                                this.tsaPassword != null && !"".equals(this.tsaPassword.trim()) && !"yourpassword".equals(this.tsaPassword.trim())) {
                            this.logger.info("Setup TSA Client with user password");
                            tsaClient = new TSAClientBouncyCastle(this.tsaURL, this.tsaUsername, this.tsaPassword);
                        }
                        if (tsaClient == null)
                            this.logger.debug("Setup TSA Client without user password");
                        tsaClient = new TSAClientBouncyCastle(this.tsaURL);
                    }
                    List<CrlClient> crlList = new ArrayList<>();
                    this.logger.debug("Try to setup CrlClient");
                    try {
                        this.logger.debug("Setup Crl Client using cert chain info");
                        CrlClient crlClient = new CrlClientOnline(chain);
                        crlList.add(crlClient);
                    } catch (Exception ignored) {}
                    if (this.crlURL != null && !"".equals(this.crlURL.trim()) && !"empty".equals(this.crlURL.trim())) {
                        this.logger.debug("Setup Crl Client using predefine url");
                        CrlClient crlClient = new CrlClientOnline(this.crlURL);
                        crlList.add(crlClient);
                    }
                    if (crlList.size() < 1) {
                        this.logger.debug("Empty Crl Client, remove crl list object");
                        crlList = null;
                    }
                    this.logger.debug("Setup spesimen rectangle");
                    Rectangle rectangle = new Rectangle(signingRequest.getVisLLX(), signingRequest.getVisLLY()
                            , signingRequest.getVisURX(), signingRequest.getVisURY());
                    try {
                        this.logger.debug("Setup spesimen image");
                        Image img = Image.getInstance(signingRequest.getSpesimenPath());
                        img.setAbsolutePosition(0.0F, 0.0F);
                        float newWidth = (signingRequest.getVisURX() - signingRequest.getVisLLX());
                        float newHeight = (signingRequest.getVisURY() - signingRequest.getVisLLY());
                        img.scaleToFit(newWidth, newHeight);
                        this.logger.debug("Finish setup spesimen image");
                        sign(signingRequest.getSrc(), signingRequest.getDest(), signingRequest.getDocpass(), chain
                                , "SHA-256", MakeSignature.CryptoStandard.CMS, signingRequest.getReason()
                                , signingRequest.getLocation(), rectangle, signingRequest.getVisSignaturePage()
                                , img, signingRequest.getCertificatelevel(), crlList, tsaClient, signerProfileName
                                , signingRequest.getJwToken(), signingRequest.getRefToken(), shaChecksum
                                , signingRequest.getRetryFlag(), trxId);
                        docFileSigningResponse = new DocFileSigningResponse();
                        docFileSigningResponse.setStatus(ConstantID.responStatusSuccess);
                        docFileSigningResponse.setErrorCode(ConstantID.errCodeSUCCESS);
                        docFileSigningResponse.setErrorMessage(ConstantID.errMsgSuccess);
                    } catch (SignAdapterException sae) {
                        docFileSigningResponse = new DocFileSigningResponse();
                        docFileSigningResponse.setStatus(ConstantID.responStatusFail);
                        docFileSigningResponse.setErrorCode(sae.getCode());
                        docFileSigningResponse.setErrorMessage(sae.getMessage());
                    } catch (Exception ex) {
                        this.logger.error("ERROR process signing ", ex);
                        docFileSigningResponse = new DocFileSigningResponse();
                        docFileSigningResponse.setStatus(ConstantID.responStatusFail);
                        docFileSigningResponse.setErrorCode(ConstantID.errCodeInternalServerError);
                        docFileSigningResponse.setErrorMessage(ex.getMessage());
                    }
                } else {
                    docFileSigningResponse = new DocFileSigningResponse();
                    docFileSigningResponse.setStatus(ConstantID.responStatusFail);
                    docFileSigningResponse.setErrorCode(ConstantID.errCodeProfilenameNotFound);
                    docFileSigningResponse.setErrorMessage("Profilename not found");
                }
            } else {
                docFileSigningResponse = new DocFileSigningResponse();
                docFileSigningResponse.setStatus(ConstantID.responStatusFail);
                docFileSigningResponse.setErrorCode(ConstantID.errCodeInvalidInput);
                docFileSigningResponse.setErrorMessage("Mandatory field(s) should not be empty");
            }
        } catch (SignAdapterException sae) {
            docFileSigningResponse = new DocFileSigningResponse();
            docFileSigningResponse.setStatus(ConstantID.responStatusFail);
            docFileSigningResponse.setErrorCode(sae.getCode());
            docFileSigningResponse.setErrorMessage(sae.getMessage());
        } catch (Exception ex) {
            this.logger.error("ERROR process signing ", ex);
            docFileSigningResponse = new DocFileSigningResponse();
            docFileSigningResponse.setStatus(ConstantID.responStatusFail);
            docFileSigningResponse.setErrorCode(ConstantID.errCodeInternalServerError);
            docFileSigningResponse.setErrorMessage(ex.getMessage());
        }
        try {
            logger.debug("[{}] response ::\n{}", trxId, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(docFileSigningResponse));
            logger.info(serviceStop(trxId, serviceName, System.currentTimeMillis()-startTime));
        } catch (Exception ignored) {}
        return new ResponseEntity<>(docFileSigningResponse, HttpStatus.OK);
    }

    private void checkAndWarningSpesificEmptyParam(DocFileSigningRequest signingRequest) {
        if (signingRequest != null) {
            String strJWT = signingRequest.getJwToken();
            if (strJWT == null || "".equals(strJWT.trim()))
                this.logger.warn("JwToken parameter is empty");
            String strRefToken = signingRequest.getRefToken();
            if (strRefToken == null || "".equals(strRefToken.trim()))
                this.logger.warn("RefToken parameter is empty");
        }
    }

    private void sign(String src, String dest, String docPass, Certificate[] chain, String digestAlgorithm
            , MakeSignature.CryptoStandard subfilter, String reason, String location, Rectangle rectangle, int visPage
            , Image img, String certificateLevel, List<CrlClient> crlList, TSAClient tsaClient, String signerProfileName
            , String jwToken, String refToken, String shaChecksum, String retryFlag, String trxId
    ) throws GeneralSecurityException, IOException, DocumentException {
        PdfReader reader;
        this.logger.debug("Entering Sign method process");
        boolean successProcess = true;
        if (docPass != null && !"".equals(docPass.trim())) {
            reader = new PdfReader(src, docPass.getBytes());
        } else {
            reader = new PdfReader(src);
        }
        int numberOfPages = reader.getNumberOfPages();
        if (numberOfPages < visPage) {
            this.logger.warn("visible page more than doc number of pages, using last page");
            visPage = numberOfPages;
        } else if (visPage < 1) {
            visPage = 1;
        }
        FileOutputStream os = new FileOutputStream(dest);
        try {
            MyExternalSignature myExternalSignature = null;
            reason = "[" + refToken + "] " + reason;
            PdfStamper stamper = null;
            if (isSignatureExist(reader)) {
                stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
            } else {
                stamper = PdfStamper.createSignature(reader, os, reader.getPdfVersion(), null, true);
            }
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason(reason);
            appearance.setLocation(location);
            String sigFieldName = "sig" + System.currentTimeMillis();
            if ("NO_CHANGES_ALLOWED".equals(certificateLevel)) {
                appearance.setCertificationLevel(1);
            } else {
                appearance.setCertificationLevel(0);
            }
            appearance.setVisibleSignature(rectangle, visPage, sigFieldName);
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.setSignatureGraphic(img);
            this.logger.debug("Prepare to create external signature");
            BouncyCastleDigest bouncyCastleDigest = new BouncyCastleDigest();
            myExternalSignature = new MyExternalSignature(signerProfileName, this.hashUrl, digestAlgorithm, jwToken
                    , refToken, this.strKeyId, shaChecksum, retryFlag, strSystemId, trxId, rtSigningService);
            try {
                MakeSignature.signDetached(appearance, bouncyCastleDigest, (ExternalSignature)myExternalSignature
                        , chain, crlList, null, tsaClient, 0, subfilter);
            } catch (SignAdapterException e) {
                throw e;
            } catch (Exception e) {
//                logger.debug("Error Signing document", e);
                String recommendC = "you can retry signing request, using same api with specified parameter 'retryFlag':'1'";
                throw new SignAdapterException(e.getMessage() + ",  *****" + recommendC, e.getCause(), ConstantID.errCodeAbnormalErrorHashSigning);
            }
        } catch (Exception e) {
//            logger.debug("Error Processing document", e);
            successProcess = false;
            throw e;
        } finally {
            try {
                reader.close();
            } catch (Exception ignored) {}
            try {
                os.close();
            } catch (Exception ignored) {}
            if (!successProcess) {
                File destFile = new File(dest);
                if (destFile.exists())
                    destFile.delete();
            }
        }
    }

    private String getFileChecksum(MessageDigest digest, File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] byteArray = new byte[1024];
        int bytesCount = 0;
        while ((bytesCount = fis.read(byteArray)) != -1)
            digest.update(byteArray, 0, bytesCount);
        fis.close();
        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++)
            sb.append(Integer.toString((bytes[i] & 0xFF) + 256, 16).substring(1));
        return sb.toString();
    }

    public boolean isSignatureExist(PdfReader reader) {
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        if (names.size() > 0)
            return true;
        return false;
    }

    public String validateOrUpgrade(String src, String destOrig, String docPass) throws SignAdapterException {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        try {
            Field algorithmNamesField = EncryptionAlgorithms.class.getDeclaredField("algorithmNames");
            algorithmNamesField.setAccessible(true);
            HashMap<String, String> algorithmNames = (HashMap<String, String>)algorithmNamesField.get(null);
            algorithmNames.put("1.2.840.10045.4.3.2", "ECDSA");
        } catch (NoSuchFieldException | IllegalAccessException e) {
            this.logger.error("Error put custom algotithm names", e);
        }
        Document document = new Document();
        PdfReader reader = null;
        String dest = src;
        int validateResult = 0;
        String exectionErrMessage = "";
        try {
            boolean blnEncrypted = false;
            if (docPass != null && !"".equals(docPass.trim())) {
                reader = new PdfReader(src, docPass.getBytes());
                blnEncrypted = true;
            } else {
                reader = new PdfReader(src);
            }
            AcroFields fields = reader.getAcroFields();
            ArrayList<String> names = fields.getSignatureNames();
            if (names.size() > 0) {
                if (reader.getCertificationLevel() == 1)
                    throw new SignAdapterException("Document already Certified, No changes are allowed", ConstantID.errCodeCertifiedDocException);
                validateResult = checkPdfIntegrity(fields);
            } else {
                if (Character.getNumericValue(reader.getPdfVersion()) >= 6)
                    return dest;
                if (blnEncrypted && Character.getNumericValue(reader.getPdfVersion()) >= 5)
                    return dest;
                if (blnEncrypted)
                    throw new SignAdapterException("Document password protected, cannot upgrade document version, please use PDF version 1.6 or above", ConstantID.errCodeUpgradeDocumentException);
                dest = destOrig + ".bckp";
                PdfSmartCopy pdfSmartCopy = new PdfSmartCopy(document, Files.newOutputStream(Paths.get(dest)));
                pdfSmartCopy.setPdfVersion('7');
                Map<String, String> info = reader.getInfo();
                if (info.get("Title") != null)
                    document.addTitle(info.get("Title"));
                if (info.get("Author") != null)
                    document.addAuthor(info.get("Author"));
                if (info.get("Subject") != null)
                    document.addSubject(info.get("Subject"));
                if (info.get("Keywords") != null)
                    document.addKeywords(info.get("Keywords"));
                if (info.get("Creator") != null)
                    document.addCreator(info.get("Creator"));
                document.open();
                for (int page = 1; page <= reader.getNumberOfPages(); page++) {
                    PdfImportedPage importedPage = pdfSmartCopy.getImportedPage(reader, page);
                    pdfSmartCopy.addPage(importedPage);
                }
                return dest;
            }
        } catch (IOException e) {
            validateResult = 4;
            exectionErrMessage = "IOException-" + e.getMessage();
            this.logger.warn("IOException while processing document with message [" + e.getMessage() + "]");
        } catch (BadPdfFormatException e) {
            validateResult = 4;
            exectionErrMessage = "BadPdfFormatException-" + e.getMessage();
            this.logger.warn("BadPdfFormatException while processing document with message [" + e.getMessage() + "]");
        } catch (DocumentException e) {
            validateResult = 4;
            exectionErrMessage = "DocumentException-" + e.getMessage();
            this.logger.warn("DocumentException while processing document with message [" + e.getMessage() + "]");
        } finally {
            try {
                document.close();
            } catch (Exception e) {
                this.logger.warn("Exception closing document with message [" + e.getMessage() + "]");
            }
            if (reader != null)
                try {
                    reader.close();
                } catch (Exception e) {
                    this.logger.warn("Exception closing reader with message [" + e.getMessage() + "]");
                }
        }
        if (validateResult == 1)
            throw new SignAdapterException("Source Document has been change since it was signed", ConstantID.errCodeIntegrityCheckRevisionFailed);
        if (validateResult == 2)
            throw new SignAdapterException("Source Document has invalid signature", ConstantID.errCodeIntegrityCheckSignatureFailed);
        if (validateResult == 3)
            throw new SignAdapterException("Failed to upgrade document version", ConstantID.errCodeUpgradeDocumentException);
        if (validateResult == 4)
            throw new SignAdapterException("Cannot upgrade document version, with message [" + exectionErrMessage + "]", ConstantID.errCodeUpgradeDocumentException);
        return src;
    }

    private int checkPdfIntegrity(AcroFields fields) {
        try {
            ArrayList<String> names = fields.getSignatureNames();
            if (names.size() > 0)
                try {
                    for (String name : names) {
                        if (!verifySignature(fields, name)) {
                            this.logger.warn("Integrity check failed for signature name [" + name + "]");
                            return 2;
                        }
                    }
                } catch (Exception exception) {
                    this.logger.error("Error while check file integrity with message : " + exception.getMessage());
                    return 2;
                }
        } catch (Exception exception) {
            this.logger.error("Error while check file integrity", exception);
            return 3;
        }
        return 0;
    }

    private boolean verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        return pkcs7.verify();
    }

    private String getCertLevelStr(int certLevel) {
        switch (certLevel) {
            case 1:
                return "CERTIFIED_NO_CHANGES_ALLOWED";
            case 2:
                return "CERTIFIED_FORM_FILLING";
            case 3:
                return "CERTIFIED_FORM_FILLING_AND_ANNOTATIONS";
        }
        return "NOT_CERTIFIED";
    }

    private String serviceStart(String trxId, String service) throws Exception {
        return "===== ["+trxId+"] [" + service + "] [S] =====";
    }

    private String serviceStop(String trxId, String service, long duration) throws Exception {
        return "===== ["+trxId+"] [" + service + "] ["+duration+"]ms [E] =====";
    }
}