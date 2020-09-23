package com.aa.opshub.azure;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import com.aa.opshub.azure.rsa.AzureRSAUtils;

@SpringBootApplication
public class App {

	public static void main(String[] args) throws Exception {

		ApplicationContext ctx = SpringApplication.run(App.class, args);
		AzureRSAUtils rsaUtil = ctx.getBean(AzureRSAUtils.class);
		System.err.println(rsaUtil.encryptKey("TextToEncrypt".getBytes()));

	}
}