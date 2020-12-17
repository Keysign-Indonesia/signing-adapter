package com.mjh.adapter.signing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SpringBootApplication
public class SigningApplication {
	private static Logger logger = LoggerFactory.getLogger(SigningApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SigningApplication.class, args);
	}

}
