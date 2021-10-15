package com.mjh.adapter.signing.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import com.mjh.adapter.signing.model.DocFileSigningRequest;
import com.mjh.adapter.signing.model.DocFileSigningResponse;
import com.mjh.adapter.signing.utils.MyExternalSignature;
import com.mjh.adapter.signing.utils.MyOldExternalSignature;
import com.mjh.adapter.signing.utils.MyUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/adapter/pdfsigning/rest")
@Api(value="Signing Adapter Service", description="Operations to signing document")
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

    Logger logger = LoggerFactory.getLogger(SigningAdapterService.class);

    @PostMapping("/docSigningZ")
    @ApiOperation(value = "Signing Document File Rest Service", response = DocFileSigningResponse.class)
    public @ResponseBody
    DocFileSigningResponse docSigningZ(@RequestBody DocFileSigningRequest signingRequest) throws Exception
    {
        DocFileSigningResponse docFileSigningResponse;
        ObjectMapper mapper = new ObjectMapper();
        try{
            logger.info(serviceStart("docSigningZ"));
            logger.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signingRequest));
        }catch (Exception e){}

        try {

            if (signingRequest != null && ConstantID.checkInputOK.equals(signingRequest.checkInput())) {
                checkAndWarningSpesificEmptyParam(signingRequest);
                //validate integrity or upgrade document
                String newSrc = validateOrUpgrade(signingRequest.getSrc(), signingRequest.getDest(), signingRequest.getDocpass());
                if(!signingRequest.getSrc().equals(newSrc))
                    signingRequest.setSrc(newSrc);

                //get checkSum source file
                MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
                String shaChecksum = getFileChecksum(sha256Digest, new File(signingRequest.getSrc()));

                String signerProfileName = signingRequest.getProfileName();
                if(signerProfileName != null && !"".equals(signerProfileName.trim())) {

                    final List<Certificate> certs = MyUtil.getSignerCertChainRequestResponse(certChainUrl, signerProfileName, signingRequest.getJwToken(), signingRequest.getRefToken(), strKeyId);
                    Certificate[] chain = certs.toArray(new Certificate[certs.size()]);
                    logger.debug("Finish getting certificate chain");

                    TSAClient tsaClient = null;
                    logger.debug("Try setup TSAClient");
                    if(tsaURL != null && !"".equals(tsaURL.trim())) {
                        if(tsaUsername != null && !"".equals(tsaUsername.trim()) && !"yourusername".equals(tsaUsername.trim())) {
                            if (tsaPassword != null && !"".equals(tsaPassword.trim()) && !"yourpassword".equals(tsaPassword.trim())) {
                                logger.info("Setup TSA Client with user password");
                                tsaClient = new TSAClientBouncyCastle(tsaURL, tsaUsername, tsaPassword);
                            }
                        }
                        if(tsaClient == null)
                            logger.debug("Setup TSA Client without user password");
                        tsaClient = new TSAClientBouncyCastle(tsaURL);
                    }

                    List<CrlClient> crlList = new ArrayList<>();
                    logger.debug("Try to setup CrlClient");
                    try{
                        logger.debug("Setup Crl Client using cert chain info");
                        CrlClient crlClient = new CrlClientOnline(chain);
                        crlList.add(crlClient);
                    } catch (Exception e){}
                    if(crlURL != null && !"".equals(crlURL.trim()) && !"empty".equals(crlURL.trim())) {
                        logger.debug("Setup Crl Client using predefine url");
                        CrlClient crlClient = new CrlClientOnline(crlURL);
                        crlList.add(crlClient);
                    }
                    if(crlList.size()<1) {
                        logger.debug("Empty Crl Client, remove crl list object");
                        crlList = null;
                    }

                    logger.debug("Setup spesimen rectangle");
                    Rectangle rectangle = new Rectangle(signingRequest.getVisLLX(), signingRequest.getVisLLY(), signingRequest.getVisURX(), signingRequest.getVisURY());

                    try {
                        logger.debug("Setup spesimen image");
                        com.itextpdf.text.Image img = com.itextpdf.text.Image.getInstance(signingRequest.getSpesimenPath());
                        img.setAbsolutePosition(0, 0);
                        float newWidth = signingRequest.getVisURX() - signingRequest.getVisLLX();
                        float newHeight = signingRequest.getVisURY() - signingRequest.getVisLLY();
                        img.scaleToFit(newWidth, newHeight);
                        logger.debug("Finish setup spesimen image");

                        sign(signingRequest.getSrc(), signingRequest.getDest(), signingRequest.getDocpass()
                                ,chain, DigestAlgorithms.SHA256, MakeSignature.CryptoStandard.CMS
                                , signingRequest.getReason(), signingRequest.getLocation()
                                , rectangle, signingRequest.getVisSignaturePage(), img, signingRequest.getCertificatelevel()
                                , crlList, tsaClient, signerProfileName, signingRequest.getJwToken(), signingRequest.getRefToken()
                                , shaChecksum, signingRequest.getRetryFlag());

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
                        logger.error("ERROR process signing ", ex);
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
            logger.error("ERROR process signing ", ex);
            docFileSigningResponse = new DocFileSigningResponse();
            docFileSigningResponse.setStatus(ConstantID.responStatusFail);
            docFileSigningResponse.setErrorCode(ConstantID.errCodeInternalServerError);
            docFileSigningResponse.setErrorMessage(ex.getMessage());
        }

        try {
            logger.info(serviceStop("docSigningZ"));
            logger.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(docFileSigningResponse));
        }catch (Exception ex) {}

        return docFileSigningResponse;
    }

    private void checkAndWarningSpesificEmptyParam(DocFileSigningRequest signingRequest)
    {
        if(signingRequest != null){
            String strJWT = signingRequest.getJwToken();
            if(strJWT == null || "".equals(strJWT.trim())) {
                logger.warn("JwToken parameter is empty");
            }
            String strRefToken = signingRequest.getRefToken();
            if(strRefToken == null || "".equals(strRefToken.trim())) {
                logger.warn("RefToken parameter is empty");
            }
        }
    }

    private void sign(String src, String dest, String docPass,
                      java.security.cert.Certificate[] chain, String digestAlgorithm,
                      MakeSignature.CryptoStandard subfilter,
                      String reason, String location, Rectangle rectangle, int visPage,
                      com.itextpdf.text.Image img, String certificateLevel, List<CrlClient> crlList, TSAClient tsaClient,
                      String signerProfileName, String jwToken, String refToken, String shaChecksum, String retryFlag)
            throws GeneralSecurityException, IOException, DocumentException
    {
        // Creating the reader and the stamper
        logger.debug("Entering Sign method process");
        boolean successProcess = true;

        PdfReader reader;
        if(docPass != null && !"".equals(docPass.trim())) {
            reader = new PdfReader(src, docPass.getBytes());
        } else reader = new PdfReader(src);

        int numberOfPages = reader.getNumberOfPages();
        if(numberOfPages < visPage) {
            logger.warn("visible page more than doc number of pages, using last page");
            visPage = numberOfPages;
        }

        FileOutputStream os = new FileOutputStream(dest);
        try {
            //adding refToken to reason
            reason = "["+refToken+"] " + reason;

//            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
            PdfStamper stamper = null;
            if(isSignatureExist(reader))
                stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
            else
                stamper = PdfStamper.createSignature(reader, os, reader.getPdfVersion(), null, true);

            // Creating the appearance
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason(reason);
            appearance.setLocation(location);
            String sigFieldName = "sig" + System.currentTimeMillis();
            if("NO_CHANGES_ALLOWED".equals(certificateLevel))
                appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
            else
                appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);


            appearance.setVisibleSignature(rectangle, visPage, sigFieldName);
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            appearance.setSignatureGraphic(img);


            // Creating the signature
            logger.debug("Prepare to create external signature");
            ExternalDigest digest = new BouncyCastleDigest();
            ExternalSignature signature;
            if(signerProfileName.endsWith("PS"))
                signature = new MyOldExternalSignature(signerProfileName, hashUrl, digestAlgorithm, jwToken, refToken, strKeyId, shaChecksum, retryFlag);
            else
                signature = new MyExternalSignature(signerProfileName, hashUrl, digestAlgorithm, jwToken, refToken, strKeyId, shaChecksum, retryFlag);

            //catch error hash signing, and recommend client to retry on error message
            try {
                MakeSignature.signDetached(appearance, digest, signature, chain, crlList, null, tsaClient, 0, subfilter);
            } catch (Exception e){
                logger.error("Error Signing document",e);
                String recommendC = "you can retry signing request, using same api with specified parameter 'retryFlag':'1'";
                throw new SignAdapterException(ConstantID.errCodeAbnormalErrorHashSigning, e.getCause(), e.getMessage() +",  *****"+recommendC);
            }
        } catch (Exception e) {
            logger.error("Error Processing document",e);
            successProcess = false;
            throw e;
        } finally {
            if(reader != null){
                try{
                    reader.close();
                } catch (Exception e){}
            }
            if(os != null){
                try{
                    os.close();
                } catch (Exception e){}
            }
            if(!successProcess){
                File destFile = new File(dest);
                if(destFile.exists()) destFile.delete();
            }
        }
    }

    private String getFileChecksum(MessageDigest digest, File file) throws IOException
    {
        //Get file input stream for reading the file content
        FileInputStream fis = new FileInputStream(file);

        //Create byte array to read data in chunks
        byte[] byteArray = new byte[1024];
        int bytesCount = 0;

        //Read file data and update in message digest
        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        };

        //close the stream; We don't need it now.
        fis.close();

        //Get the hash's bytes
        byte[] bytes = digest.digest();

        //This bytes[] has bytes in decimal format;
        //Convert it to hexadecimal format
        StringBuilder sb = new StringBuilder();
        for(int i=0; i< bytes.length ;i++)
        {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        //return complete hash
        return sb.toString();
    }

    public boolean isSignatureExist(PdfReader reader)
    {
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        if(names.size()>0) return true;
        return false;
    }

    public String validateOrUpgrade(String src, String destOrig, String docPass) throws SignAdapterException
    {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        Document document = new Document();
        PdfReader reader = null;

        String dest = src;
        int validateResult = 0;
        try {
            reader = new PdfReader(src);
            boolean blnEncrypted = false;

            //not clone encrypted doc
            if(reader.isEncrypted())
                blnEncrypted = true;

            if(docPass != null && !"".equals(docPass.trim())) {
                reader = new PdfReader(src, docPass.getBytes());
            } else reader = new PdfReader(src);

            AcroFields fields = reader.getAcroFields();
            ArrayList<String> names = fields.getSignatureNames();
            if(names.size()>0)
            {
                //check certificate level, not equal 1 or NO CHANGES ALLOWED
                if(reader.getCertificationLevel() == 1)
                    throw new SignAdapterException("Document already Certified, No changes are allowed", ConstantID.errCodeCertifiedDocException);

                validateResult = checkPdfIntegrity(fields);
            } else {
                if(blnEncrypted) return dest;
                if(Character.getNumericValue(reader.getPdfVersion())>=6) return dest;

                dest = destOrig + ".bckp";
                PdfCopy copy = new PdfSmartCopy(document, new FileOutputStream(dest));
                copy.setPdfVersion(PdfWriter.VERSION_1_7);

                Map<String, String> info = reader.getInfo();
                if(info.get("Title") != null)
                    document.addTitle(info.get("Title"));
                if(info.get("Author") != null)
                    document.addAuthor(info.get("Author"));
                if(info.get("Subject") != null)
                    document.addSubject(info.get("Subject"));
                if(info.get("Keywords") != null)
                    document.addKeywords(info.get("Keywords"));
                if(info.get("Creator") != null)
                    document.addCreator(info.get("Creator"));

                document.open();
                for(int page = 1; page <= reader.getNumberOfPages(); page++) {
                    PdfImportedPage importedPage = copy.getImportedPage(reader, page);
                    copy.addPage(importedPage);
                }

                return dest;
            }
        } catch (IOException e) {
            logger.warn("IOException while processing document with message ["+e.getMessage()+"]");
        } catch (BadPdfFormatException e) {
            logger.warn("BadPdfFormatException while processing document with message ["+e.getMessage()+"]");
        } catch (DocumentException e) {
            logger.warn("DocumentException while processing document with message ["+e.getMessage()+"]");
        } finally {
            if(document != null){
                try{document.close();} catch (Exception e) {
                    logger.warn("Exception closing document with message ["+e.getMessage()+"]");
                }
                if(reader != null){
                    try{reader.close();} catch (Exception e) {
                        logger.warn("Exception closing reader with message ["+e.getMessage()+"]");
                    }
                }
            }
        }
        if(validateResult == 1){
            throw new SignAdapterException("Source Document has been change since it was signed", ConstantID.errCodeIntegrityCheckRevisionFailed);
        } else if(validateResult == 2){
            throw new SignAdapterException("Source Document has invalid signature", ConstantID.errCodeIntegrityCheckSignatureFailed);
        } else if(validateResult == 3){
            throw new SignAdapterException("Failed to upgrade document version", ConstantID.errCodeUpgradeDocumentException);
        }
        return src;
    }

    //return int status {0:valid, 1: revision failed, 2: Signature Failed, 3:exception}
    private int checkPdfIntegrity(AcroFields fields)
    {
        try {
            ArrayList<String> names = fields.getSignatureNames();
            if(names.size()>0){
                if(fields.getTotalRevisions() == names.size()){
                    try {
                        for (String name : names) {
                            if(!verifySignature(fields, name)){
                                logger.warn("Integrity check failed for signature name ["+name+"]");
                                return 2;
                            }
                        }
                    }  catch (Exception exception) {
                        logger.error("Error while check file integrity with message : "+exception.getMessage());
                        return 2;
                    }
                } else {
                    logger.warn("Revision integrity check failed, "+names.size()+" Signature but found "+fields.getTotalRevisions()+" revision");
                    return 1;
                }
            }
        } catch (Exception exception) {
            logger.error("Error while check file integrity", exception);
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
            default:
                return "NOT_CERTIFIED";
        }
    }

        private String serviceStart(String service) throws Exception {
        return "===== " + service + " [S] =====";
    }
    private String serviceStop(String service) throws Exception {
        return "===== " + service + " [E] =====";
    }
}
