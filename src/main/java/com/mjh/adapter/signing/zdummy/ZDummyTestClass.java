package com.mjh.adapter.signing.zdummy;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.EncryptionAlgorithms;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class ZDummyTestClass {
//    static Logger logger = LoggerFactory.getLogger(ZDummyTestClass.class);

    public static void main(String[] args) {
        try {
//            System.out.println("Hasil validasi: "+ validasiFileIni("/home/jimbonk2000/temp/keystamp/Issue/Pembayaran TA.pdf"));
//            System.out.println("\n=============================\n");
//            System.out.println("Hasil validasi: "+ validasiFileIni("/home/jimbonk2000/temp/keystamp/Issue/sampledoc.pdf"));
//            System.out.println("\n=============================\n");
            System.out.println("Hasil validasi: "+ validasiFileIni("/home/jimbonk2000/Documents/KeySign-Hash/issues/application (11).pdf"));
        } catch (Exception e) {
            System.out.println("Error validasi: "+e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static String validasiFileIni(String src){
        String destOrig = src+".dest";
        String docPass = null;
        System.out.println("Process validation of:\nsrc: "+src+"\ndestOrig: "+destOrig+"\ndocPass: "+docPass);
        try {
            String validasiResult = validateOrUpgrade(src, destOrig, docPass);
            if(src.equals(validasiResult)){
                validasiResult = "Lolos validasi tanpa upgrade";
            } else {
                System.out.println("Upgrade Source: "+validasiResult);
                validasiResult = "Lolos validasi dengan upgrade versi pdf";
            }
            return validasiResult;
        } catch (SignAdapterException e) {
            System.out.println("Error validasi: "+e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static String validateOrUpgrade(String src, String destOrig, String docPass) throws SignAdapterException {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider((Provider)providerBC);
        try {
            Field algorithmNamesField = EncryptionAlgorithms.class.getDeclaredField("algorithmNames");
            algorithmNamesField.setAccessible(true);
            HashMap<String, String> algorithmNames = (HashMap<String, String>)algorithmNamesField.get(null);
            algorithmNames.put("1.2.840.10045.4.3.2", "ECDSA");
        } catch (NoSuchFieldException e) {
            System.out.println("Error put custom algotithm names "+ e.getMessage());
        } catch (IllegalAccessException e) {
            System.out.println("Error put custom algotithm names " + e.getMessage());
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
            System.out.println("Dokumen versi: "+Character.getNumericValue(reader.getPdfVersion()));
            if (names.size() > 0) {
                System.out.println("Dokumen memiliki "+names.size()+" signature");
                System.out.println("Dokumen memiliki "+fields.getTotalRevisions()+" revision");
                if (reader.getCertificationLevel() == 1)
                    throw new SignAdapterException("Document already Certified, No changes are allowed", ConstantID.errCodeCertifiedDocException);
                validateResult = checkPdfIntegrity(fields);
            } else {
                if (Character.getNumericValue(reader.getPdfVersion()) >= 6)
                    return dest;
                if (blnEncrypted)
                    throw new SignAdapterException("Document password protected, cannot upgrade document version, please use PDF version 1.6 or above", ConstantID.errCodeUpgradeDocumentException);
                dest = destOrig + ".bckp";
                PdfSmartCopy pdfSmartCopy = new PdfSmartCopy(document, new FileOutputStream(dest));
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
            System.out.println("IOException while processing document with message [" + e.getMessage() + "]");
        } catch (BadPdfFormatException e) {
            validateResult = 4;
            exectionErrMessage = "BadPdfFormatException-" + e.getMessage();
            System.out.println("BadPdfFormatException while processing document with message [" + e.getMessage() + "]");
        } catch (DocumentException e) {
            validateResult = 4;
            exectionErrMessage = "DocumentException-" + e.getMessage();
            System.out.println("DocumentException while processing document with message [" + e.getMessage() + "]");
        } finally {
            if (document != null) {
                try {
                    document.close();
                } catch (Exception e) {
                    System.out.println("Exception closing document with message [" + e.getMessage() + "]");
                }
                if (reader != null)
                    try {
                        reader.close();
                    } catch (Exception e) {
                        System.out.println("Exception closing reader with message [" + e.getMessage() + "]");
                    }
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


    private static int checkPdfIntegrity(AcroFields fields) {
        try {
            ArrayList<String> names = fields.getSignatureNames();
            if (names.size() > 0)
                try {
                    for (String name : names) {
                        System.out.print("Signature ["+name+"] is ");
                        if (!verifySignature(fields, name)) {
                            System.out.println("Not Valid");
                            System.out.println("Integrity check failed for signature name [" + name + "]");
                            return 2;
                        }
                        System.out.println("Valid");
                    }
                } catch (Exception exception) {
                    System.out.println("Error while check file integrity with message : " + exception.getMessage());
                    return 2;
                }
        } catch (Exception exception) {
            System.out.println("Error while check file integrity "+exception.getMessage());
            return 3;
        }
        return 0;
    }


    private static boolean verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        return pkcs7.verify();
    }

}
