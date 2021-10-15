package com.mjh.adapter.signing.utils;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpStatus;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MyUtil {
    private static final Logger logger = LoggerFactory.getLogger(MyUtil.class);

    public static String base64encode(byte[] value) {
        return new String(Base64.encodeBase64(value));
    }

    public static byte[] base64decode(String value) {
        return Base64.decodeBase64(value);
    }

    public static String utilBase64encode(byte[] value) {
        return new String(java.util.Base64.getEncoder().encode(value));
    }

    public static byte[] utilBase64decode(String value) {
        return java.util.Base64.getDecoder().decode(value);
    }

    public static String POSTHashRequestResponse(String urlEndpoint, String workerName
            , String processData, String jwToken, String refToken
            , String keyId, String shaChecksum, String retryFlag) throws SignAdapterException, Exception
    {
        if(urlEndpoint == null) urlEndpoint = "http://localhost:9999/rest/hashSigning";
        logger.info("url : "+ urlEndpoint);
        final String POST_PARAMS = "{\n"
                + "\"systemId\": \"DJP-METERAI\", "
                + "\"workerName\": \""+workerName+"\", "
                + "\"data\": \""+processData+"\", "
                + "\"shaChecksum\": \""+(shaChecksum!=null?shaChecksum:"")+"\", "
                + "\"retryFlag\": \""+(retryFlag!=null?retryFlag:"")+"\", "
                + "\"jwToken\": \""+(jwToken!=null?jwToken:"")+"\", "
                + "\"refToken\": \""+(refToken!=null?refToken:"")+"\""
                + "\n}";

        if(keyId == null || !"".equals(keyId.trim()))
        {
            keyId = "6d7a673f-ec98-40cf-a1a1-dc9966992c78";
        }
        logger.info("Param : " + POST_PARAMS);
        try {
            trustAllCert();
            URL obj = new URL(urlEndpoint);
            HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
            postConnection.setRequestMethod("POST");
            postConnection.setRequestProperty("Content-Type", "application/json");
            postConnection.setRequestProperty("x-Gateway-APIKey", keyId);
            if(jwToken!=null && !"".equals(jwToken.trim())){
                postConnection.setRequestProperty("Authorization", "Bearer "+jwToken);
            }
            postConnection.setDoOutput(true);
            OutputStream os = postConnection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = postConnection.getResponseCode();
            logger.info("POST Response Code :  " + responseCode);
            logger.debug("POST Response Message : " + postConnection.getResponseMessage());
            if (responseCode == HttpURLConnection.HTTP_CREATED
                    || responseCode == HttpURLConnection.HTTP_OK)
            { //success
                BufferedReader in = new BufferedReader(new InputStreamReader(
                        postConnection.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in .readLine()) != null) {
                    response.append(inputLine);
                } in .close();
                // print result
                logger.debug(response.toString());
                System.out.println(response.toString());
                JSONObject jsonObject = new JSONObject(response.toString());

                boolean invokeSuccess = true;
                String statusCode = "00";
                try {
                    invokeSuccess = jsonObject.getBoolean("status");
                } catch (Exception ex){}
                try {
                    statusCode = jsonObject.getString("statusCode");
                } catch (Exception ex){}

                if(!invokeSuccess){
                    String result = "Internal Signing Server Error";
                    try{
                        result = jsonObject.getString("errorMessage");
                    } catch (Exception ex){}
                    throw new SignAdapterException("Error while signing ["+result+"]", ConstantID.errCodePostHashSigning);
                }
                if(!statusCode.equals("00")){
                    String result = ConstantID.errInternalApiServer;
                    try{
                        result = jsonObject.getString("result");
                    } catch (Exception ex){}
                    if(!ConstantID.errInternalApiServer.equals(result))
                        throw new SignAdapterException("Error while signing ["+result+"]", statusCode);
                    else
                        throw new SignAdapterException("Error while signing ["+result+"]", ConstantID.errCodePostHashSigning);
                }

                try{
                    logger.info("Sign ArchiveID : "+ jsonObject.getString("archiveId"));
                }catch (Exception ex){}

                try {
                    return jsonObject.getString("data");
                } catch (Exception e) {
                    logger.error("***Exception get field data response :: \n" + response.toString());
                    throw e;
                }
            } else {
                logger.warn("Failed invoke service");
                String responseMessage = HttpStatus.getStatusText(responseCode);
                throw new SignAdapterException("Http status ["+responseCode+"] : "+responseMessage, ConstantID.errCodePostHashSigning);
            }
        } catch (SignAdapterException e) {
            throw e;
        }catch (Exception ex) {
            throw new SignAdapterException("Error while signing process ["+ex.getMessage()+"]", ex.getCause(), ConstantID.errCodePostHashSigning);
        }
    }

    public static List<Certificate> getSignerCertChainRequestResponse(String urlEndpoint, String profileName, String jwToken, String refToken, String keyId) throws SignAdapterException, Exception
    {
        if(urlEndpoint == null) urlEndpoint = "http://localhost:9999/rest/getSignerCertChain";
        logger.info("url : "+ urlEndpoint);
        final String POST_PARAMS = "{\n"
                + "\"systemId\": \"DJP-METERAI\", "
                + "\"profileName\": \""+profileName+"\", "
                + "\"jwToken\": \""+(jwToken!=null?jwToken:"")+"\", "
                + "\"refToken\": \""+(refToken!=null?refToken:"")+"\""
                + "\n}";

        logger.info("Param : " + POST_PARAMS);
        if(keyId == null || !"".equals(keyId.trim()))
        {
            keyId = "6d7a673f-ec98-40cf-a1a1-dc9966992c78";
        }
        try{
            trustAllCert();
            URL obj = new URL(urlEndpoint);
            HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
            postConnection.setRequestMethod("POST");
            postConnection.setRequestProperty("Content-Type", "application/json");
            postConnection.setRequestProperty("x-Gateway-APIKey", keyId);
            if(jwToken!=null && !"".equals(jwToken.trim())){
                postConnection.setRequestProperty("Authorization", "Bearer "+jwToken);
            }
            postConnection.setDoOutput(true);
            OutputStream os = postConnection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = postConnection.getResponseCode();
            logger.info("POST Response Code :  " + responseCode);
            logger.debug("POST Response Message : " + postConnection.getResponseMessage());
            if (responseCode == HttpURLConnection.HTTP_CREATED
                    || responseCode == HttpURLConnection.HTTP_OK)
            { //success
                List<Certificate> certs = new ArrayList<>();

                BufferedReader in = new BufferedReader(new InputStreamReader(
                        postConnection.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in .readLine()) != null) {
                    response.append(inputLine);
                } in .close();
                // print result
                logger.debug(response.toString());
                System.out.println(response.toString());
                JSONObject jsonObject = new JSONObject(response.toString());

                boolean invokeSuccess = true;
                String statusCode = "00";
                try {
                    invokeSuccess = jsonObject.getBoolean("status");
                } catch (Exception ex){}
                try {
                    statusCode = jsonObject.getString("statusCode");
                } catch (Exception ex){}

                if(!invokeSuccess){
                    String result = "Internal Signing Server Error";
                    try{
                        result = jsonObject.getString("errorMessage");
                    } catch (Exception ex){}
                    throw new SignAdapterException("Error while signing ["+result+"]", ConstantID.errCodeGetCertChain);
                }
                if(!statusCode.equals("00")){
                    String result = ConstantID.errInternalApiServer;
                    try{
                        result = jsonObject.getString("result");
                    } catch (Exception ex){}
                    if(!ConstantID.errInternalApiServer.equals(result))
                        throw new SignAdapterException("Error while signing ["+result+"]", statusCode);
                    else
                        throw new SignAdapterException("Error while signing ["+result+"]", ConstantID.errCodeGetCertChain);
                }

                JSONArray entriesArray = (JSONArray) jsonObject.get("certs");
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                for (Object i : entriesArray) {
                    // We happen to know that JSONArray contains strings.
                    byte[] inCert = base64decode(checkB64String((String) i));
                    try {
                        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(inCert));
                        X509Certificate cert = (X509Certificate) certificate;
                        logger.debug("Certificate Info : "+cert.getSerialNumber());
                        logger.debug("Certificate SigAlgName : "+cert.getSigAlgName());
                        certs.add(certificate);
                    } catch (CertificateException e) {
                        throw new SignAdapterException("Malformed certs data have been received: " + e.getLocalizedMessage(), e.getCause(), ConstantID.errCodeGetCertChain);
                    }  catch (Exception e) {
                        throw new SignAdapterException("Exception while process certificate response: " + e.getLocalizedMessage(), e.getCause(), ConstantID.errCodeGetCertChain);
                    }
                }
                return certs;
            } else {
                logger.warn("Failed invoke service");
                String responseMessage = HttpStatus.getStatusText(responseCode);
                throw new SignAdapterException("Http status ["+responseCode+"] : "+responseMessage, ConstantID.errCodeGetCertChain);
            }
        } catch (SignAdapterException e) {
            throw e;
        } catch (Exception ex) {
            throw new SignAdapterException(ex.getMessage(), ex.getCause(),ConstantID.errCodeGetCertChain);
        }
    }

    public static List<Certificate> getSignerCertificateRequestResponse(String urlEndpoint, String profileName, String jwToken, String refToken, String keyId) throws SignAdapterException, Exception
    {
        if(urlEndpoint == null) urlEndpoint = "http://localhost:9999/rest/getSignerCertificate";
        logger.info("url : "+ urlEndpoint);
        final String POST_PARAMS =
                "{\n"
                        + "\"systemId\": \"DJP-METERAI\", "
                        + "\"profileName\": \""+profileName+"\", "
                        + "\"jwToken\": \""+(jwToken!=null?jwToken:"")+"\", "
                        + "\"refToken\": \""+(refToken!=null?refToken:"")+"\""
                        + "\n}";
        logger.info("Param : " + POST_PARAMS);
        if(keyId == null || !"".equals(keyId.trim()))
        {
            keyId = "6d7a673f-ec98-40cf-a1a1-dc9966992c78";
        }

        try{
            trustAllCert();
            URL obj = new URL(urlEndpoint);
            HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
            postConnection.setRequestMethod("POST");
            postConnection.setRequestProperty("Content-Type", "application/json");
            postConnection.setRequestProperty("x-Gateway-APIKey", keyId);
            if(jwToken!=null && !"".equals(jwToken.trim())){
                postConnection.setRequestProperty("Authorization", "Bearer "+jwToken);
            }
            postConnection.setDoOutput(true);
            OutputStream os = postConnection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = postConnection.getResponseCode();
            logger.info("POST Response Code :  " + responseCode);
            logger.debug("POST Response Message : " + postConnection.getResponseMessage());
            if (responseCode == HttpURLConnection.HTTP_CREATED
                    || responseCode == HttpURLConnection.HTTP_OK)
            { //success
                List<Certificate> certs = new ArrayList<>();

                BufferedReader in = new BufferedReader(new InputStreamReader(
                        postConnection.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in .readLine()) != null) {
                    response.append(inputLine);
                } in .close();
                // print result
                logger.debug(response.toString());
//                System.out.println(response.toString());
                JSONObject jsonObject = new JSONObject(response.toString());

                boolean invokeSuccess = true;
                String statusCode = "00";
                try {
                    invokeSuccess = jsonObject.getBoolean("status");
                } catch (Exception ex){}
                try {
                    statusCode = jsonObject.getString("statusCode");
                } catch (Exception ex){}
                if(!invokeSuccess){
                    String result = "Internal Signing Server Error";
                    try{
                        result = jsonObject.getString("errorMessage");
                    } catch (Exception ex){}
                    throw new SignAdapterException("Error while signing ["+result+"]", ConstantID.errCodeGetCertificate);
                }
                if(!statusCode.equals("00")){
                    String result = ConstantID.errInternalApiServer;
                    try{
                        result = jsonObject.getString("result");
                    } catch (Exception ex){}
                    if(!ConstantID.errInternalApiServer.equals(result))
                        throw new SignAdapterException("Error while signing ["+result+"]", statusCode);
                    else
                        throw new SignAdapterException("Error while signing ["+result+"]", ConstantID.errCodeGetCertificate);
                }

                JSONArray entriesArray = (JSONArray) jsonObject.get("certs");
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                for (Object i : entriesArray) {
                    // We happen to know that JSONArray contains strings.
                    byte[] inCert = base64decode(checkB64String((String) i));
                    try {
                        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(inCert));
                        X509Certificate cert = (X509Certificate) certificate;
                        logger.debug("Certificate Info : "+cert.getSerialNumber());
                        logger.debug("Certificate SigAlgName : "+cert.getSigAlgName());
                        certs.add(certificate);
                    } catch (CertificateException e) {
                        throw new SignAdapterException("Malformed certs data have been received: " + e.getLocalizedMessage(), ConstantID.errCodeGetCertificate);
                    }  catch (Exception e) {
                        throw new SignAdapterException("Exception while process certificate response: " + e.getLocalizedMessage(), e.getCause(), ConstantID.errCodeGetCertificate);
                    }
                }
                return certs;
            } else {
                logger.warn("Failed invoke service");
                String responseMessage = HttpStatus.getStatusText(responseCode);
                throw new SignAdapterException("Http status ["+responseCode+"] : "+responseMessage, ConstantID.errCodeGetCertificate);
            }
        } catch (SignAdapterException e) {
            throw e;
        } catch (Exception ex) {
            throw new SignAdapterException(ex.getMessage(),ConstantID.errCodeGetCertificate);
        }
    }

    private static String readErrorStream(InputStream errorStream) throws IOException
    {
        BufferedReader br = null;
        if (errorStream != null){
            br = new BufferedReader(new InputStreamReader(errorStream));
        }else{
            return null;
        }
        String response = "";
        String nachricht;
        while ((nachricht = br.readLine()) != null){
            response += nachricht;
        }
        return response;
    }

    private static void trustAllCert()
    {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            logger.error("Error trust cert ", e);
        }
    }

    private static String checkB64String(String inputCheck) throws Exception {
        String check = inputCheck;
        check = check.replace("\\u003d", "=");
        check = check.replace("\\n", "\n");
        return check;
    }

    public static void main(String[] args) throws Exception {
        try {
//            getSignerCertChainRequestResponse(null, "signerprofile");
//            getSignerCertificateRequestResponse("https://signing.keysign.my.id/keysign/pdfsigning/rest/getSignerCertificate", "20201113emeteraicertificate23PS", null, null, null);
            getSignerCertChainRequestResponse("https://signing.keysign.my.id/keysign/pdfsigning/rest/getSignerCertChain", "20201113emeteraicertificate23PS", null, null, null);

        } catch (SignAdapterException e) {
            System.err.println("Error Code : "+e.getCode());
            System.err.println("Error Message : "+e.getMessage());
            e.printStackTrace();

        } catch (Exception ex) {
            System.err.println("Error Message : "+ex.getMessage());
            ex.printStackTrace();
        }
    }

}
