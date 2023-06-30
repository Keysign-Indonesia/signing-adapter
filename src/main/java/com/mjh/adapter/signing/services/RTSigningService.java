package com.mjh.adapter.signing.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import com.mjh.adapter.signing.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

@Service
public class RTSigningService {
    private final Logger logger = LoggerFactory.getLogger(RTSigningService.class);

    @Autowired
    private RestTemplate restTemplate;

    public ServerSigningResponse POSTHashV3RequestResponse
            (String urlEndpoint, String profileName, String processData, String jwToken
                    , String refToken, String systemId, String keyId, String shaChecksum
                    , String retryFlag, String trxId) throws SignAdapterException {
        ObjectMapper mapper = new ObjectMapper();
        HttpHeaders headers = getHeaders();
        String token = "Bearer " + jwToken;
        headers.set("x-Gateway-APIKey", keyId);
        headers.set("Authorization", token);

        SigningRequest signingRequest = new SigningRequest();
        signingRequest.setWorkerName(profileName);
        signingRequest.setData(processData);
        signingRequest.setShaChecksum(shaChecksum);
        signingRequest.setSystemId(systemId);
        signingRequest.setRefToken(refToken);
        signingRequest.setRetryFlag(retryFlag);

        HttpEntity<SigningRequest> request = new HttpEntity<>(signingRequest, headers);
        if(logger.isDebugEnabled()) {
            try {
                logger.debug("[{}] Signing request:: \n{}", trxId, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signingRequest));
            } catch (Exception ignored) {}
        }

        ResponseEntity<ServerSigningResponse> response = restTemplate.postForEntity(urlEndpoint, request , ServerSigningResponse.class);
        ServerSigningResponse signingResponse = response.getBody();
        if(logger.isDebugEnabled()) {
            try {
                logger.debug("[{}] Signing server response:: \n{}", trxId, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signingResponse));
            } catch (Exception ignored) {}
        }

        if(HttpStatus.OK.equals(response.getStatusCode()) && signingResponse != null){
            if(!"00".equals(signingResponse.getErrorCode())) {
                logger.warn("TrxID [{}] Failed invoke service dataSigning with Error Code [{}] and message [{}]", trxId
                        , signingResponse.getErrorCode(), signingResponse.getErrorMessage());
                if(signingResponse.getErrorCode() != null && !"".equals(signingResponse.getErrorCode().trim())
                        && signingResponse.getErrorMessage() != null && !"".equals(signingResponse.getErrorMessage().trim())
                ){
                    throw new SignAdapterException(signingResponse.getErrorMessage(), signingResponse.getErrorCode());
                } else {
                    throw new SignAdapterException("Error while signing [" + signingResponse.getErrorMessage() + "]", signingResponse.getErrorCode());
                }
            }
            return signingResponse;
        } else {
            logger.warn("TrxID [{}] Failed invoke service", trxId);
            throw new SignAdapterException("Http status [" + response.getStatusCodeValue() + "] : Not Success", ConstantID.errCodePostHashSigning);
        }
    }

    private HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    public List<Certificate> getSignerCertChainRequestResponse(String urlEndpoint, String profileName
            , String jwToken, String refToken, String systemId, String keyId
            , String trxId) throws SignAdapterException {
        GetSignerCertChainResponse signerCertChain = getSignerCertChain(urlEndpoint, profileName, jwToken, refToken, systemId, keyId, trxId);

        List<Certificate> certs = new ArrayList<>();
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new SignAdapterException(e.getMessage(), ConstantID.errCodeGetCertChain);
        }
        for(byte[] certByte: signerCertChain.getCerts()) {
            Certificate certificate = null;
            try {
                certificate = certFactory.generateCertificate(new ByteArrayInputStream(certByte));
            } catch (CertificateException e) {
                throw new SignAdapterException(e.getMessage(), ConstantID.errCodeGetCertChain);
            }
            certs.add(certificate);
        }
        return certs;
    }

    public GetSignerCertChainResponse getSignerCertChain(String urlEndpoint, String profileName
            , String jwToken, String refToken, String systemId, String keyId
            , String trxId) throws SignAdapterException {

        HttpHeaders headers = getHeaders();
        String token = "Bearer " + jwToken;
        headers.set("x-Gateway-APIKey", keyId);
        headers.set("Authorization", token);

        GetSignerCertChainRequest signerCertChainRequest = new GetSignerCertChainRequest();
        signerCertChainRequest.setProfileName(profileName);
        signerCertChainRequest.setSystemId(systemId);
        signerCertChainRequest.setRefToken(refToken);

        HttpEntity<GetSignerCertChainRequest> request = new HttpEntity<>(signerCertChainRequest, headers);

        ResponseEntity<GetSignerCertChainResponse> response = restTemplate.postForEntity(urlEndpoint, request , GetSignerCertChainResponse.class);
        GetSignerCertChainResponse signerCertChainResponse = response.getBody();

        if(logger.isDebugEnabled()) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                logger.debug("[{}] GetCertChain server response:: \n{}", trxId, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signerCertChainResponse));
            } catch (Exception ignored) {}
        }

        if(HttpStatus.OK.equals(response.getStatusCode()) && signerCertChainResponse != null){
            if(!"00".equals(signerCertChainResponse.getErrorCode())) {
                logger.warn("TrxID [{}] Failed invoke service GetSignerCertChain with Error Code [{}]", trxId, signerCertChainResponse.getErrorCode());
                if(signerCertChainResponse.getErrorCode() != null && !"".equals(signerCertChainResponse.getErrorCode().trim())
                        && signerCertChainResponse.getErrorMessage() != null && !"".equals(signerCertChainResponse.getErrorMessage().trim())
                ){
                    throw new SignAdapterException(signerCertChainResponse.getErrorMessage(), signerCertChainResponse.getErrorCode());
                } else {
                    throw new SignAdapterException("Error while get signer certificate chain [" + signerCertChainResponse.getErrorMessage() + "]", signerCertChainResponse.getErrorCode());
                }
            }
            return signerCertChainResponse;
        } else {
            logger.warn("TrxID [{}] Failed invoke service, Http Status [{}]", trxId, response.getStatusCodeValue());
            if(signerCertChainResponse!= null
                    && signerCertChainResponse.getErrorCode() != null && "".equals(signerCertChainResponse.getErrorCode().trim())
                    && signerCertChainResponse.getErrorMessage() != null && "".equals(signerCertChainResponse.getErrorMessage().trim())
            ){
                throw new SignAdapterException(signerCertChainResponse.getErrorMessage(), signerCertChainResponse.getErrorCode());
            } else {
                throw new SignAdapterException("Http status [" + response.getStatusCodeValue() + "] : Not Success", ConstantID.errCodeGetCertChain);
            }
        }
    }
}