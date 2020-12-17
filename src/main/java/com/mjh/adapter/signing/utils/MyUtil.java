package com.mjh.adapter.signing.utils;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MyUtil {
    private static final Logger logger = LoggerFactory.getLogger(MyUtil.class);

    public static String base64encode(byte[] value) {
        return new String(Base64.getEncoder().encode(value));
    }

    public static byte[] base64decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static String POSTHashRequestResponse(String urlEndpoint, String workerName, String processData, String jwToken, String refToken) throws IOException {
        if(urlEndpoint == null) urlEndpoint = "http://localhost:9999/rest/hashSigning";
        logger.info("url : "+ urlEndpoint);
        final String POST_PARAMS =
                "{\n"
                        + "\"workerName\": \""+workerName+"\", "
                        + "\"data\": \""+processData+"\","
                        + "\"jwToken\": \""+(jwToken!=null?jwToken:"")+"\","
                        + "\"refToken\": \""+(refToken!=null?refToken:"")+"\""
                        + "\n}";
        logger.info("Param : " + POST_PARAMS);
        trustAllCert();
        URL obj = new URL(urlEndpoint);
        HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
        postConnection.setRequestMethod("POST");
        postConnection.setRequestProperty("Content-Type", "application/json");
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
            JSONObject jsonObject = new JSONObject(response.toString());

            return jsonObject.getString("data");
        } else {
            logger.warn("POST NOT WORKED");
        }
        return null;
    }

    public static List<Certificate> getSignerCertChainRequestResponse(String urlEndpoint, String profileName, String jwToken, String refToken) throws Exception {
        if(urlEndpoint == null) urlEndpoint = "http://localhost:9999/rest/getSignerCertChain";
        logger.info("url : "+ urlEndpoint);
        final String POST_PARAMS =
                "{\n"
                        + "\"profileName\": \""+profileName+"\","
                        + "\"jwToken\": \""+(jwToken!=null?jwToken:"")+"\","
                        + "\"refToken\": \""+(refToken!=null?refToken:"")+"\""
                        + "\n}";
        logger.info("Param : " + POST_PARAMS);
        trustAllCert();
        URL obj = new URL(urlEndpoint);
        HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
        postConnection.setRequestMethod("POST");
        postConnection.setRequestProperty("Content-Type", "application/json");
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
            JSONObject jsonObject = new JSONObject(response.toString());
            JSONArray entriesArray = (JSONArray) jsonObject.get("certs");

            for (Object i : entriesArray) {
                // We happen to know that JSONArray contains strings.
                byte[] inCert = base64decode((String) i);
                try {
                    Certificate certificate = CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(inCert));
                    X509Certificate cert = (X509Certificate) certificate;
                    logger.debug("Certificate Info : "+cert.getSerialNumber());
                    logger.debug("Certificate SigAlgName : "+cert.getSigAlgName());
                    certs.add(certificate);
                } catch (CertificateException e) {
                    throw new Exception("Malformed certs data have been received: " + e.getLocalizedMessage());
                }
            }
            return certs;
        } else {
            logger.debug("POST NOT WORKED");
        }
        return null;
    }

    public static List<Certificate> getSignerCertificateRequestResponse(String urlEndpoint, String profileName, String jwToken, String refToken) throws Exception {
        if(urlEndpoint == null) urlEndpoint = "http://localhost:9999/rest/getSignerCertificate";
        logger.info("url : "+ urlEndpoint);
        final String POST_PARAMS =
                "{\n"
                        + "\"profileName\": \""+profileName+"\","
                        + "\"jwToken\": \""+(jwToken!=null?jwToken:"")+"\","
                        + "\"refToken\": \""+(refToken!=null?refToken:"")+"\""
                        + "\n}";
        logger.info("Param : " + POST_PARAMS);
        trustAllCert();
        URL obj = new URL(urlEndpoint);
        HttpURLConnection postConnection = (HttpURLConnection) obj.openConnection();
        postConnection.setRequestMethod("POST");
        postConnection.setRequestProperty("Content-Type", "application/json");
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
            JSONObject jsonObject = new JSONObject(response.toString());
            JSONArray entriesArray = (JSONArray) jsonObject.get("certs");

            for (Object i : entriesArray) {
                // We happen to know that JSONArray contains strings.
                byte[] inCert = base64decode((String) i);
                try {
                    Certificate certificate = CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(inCert));
                    X509Certificate cert = (X509Certificate) certificate;
                    logger.debug("Certificate Info : "+cert.getSerialNumber());
                    logger.debug("Certificate SigAlgName : "+cert.getSigAlgName());
                    certs.add(certificate);
                } catch (CertificateException e) {
                    throw new Exception("Malformed certs data have been received: " + e.getLocalizedMessage());
                }
            }
            return certs;
        } else {
            logger.debug("POST NOT WORKED");
        }
        return null;
    }


    private static void trustAllCert() {
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

    public static void main(String[] args) throws Exception {
//        getSignerCertChainRequestResponse(null, "signerprofile");
        getSignerCertChainRequestResponse("https://signing.keysign.my.id/keysign/pdfsigning/rest/getSignerCertChain", "20201113emeteraicertificate23PS", null, null);
    }

}
