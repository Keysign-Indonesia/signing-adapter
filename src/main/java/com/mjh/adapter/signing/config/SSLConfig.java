package com.mjh.adapter.signing.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;

@Configuration
public class SSLConfig {
    @Value("${my.truststore}")
    private String truststore;
    @Value("${my.truststore.password}")
    private String truststorePass;

    @PostConstruct
    private void configureSSL() {
        System.setProperty("https.protocols", "TLSv1.1,TLSv1.2");
        System.setProperty("javax.net.ssl.trustStore", truststore);
        System.setProperty("javax.net.ssl.trustStorePassword",truststorePass);
    }

}
