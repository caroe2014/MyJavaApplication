package com.aa.opshub.azure.rsa;

import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AppServiceMSICredentials;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.windowsazure.core.pipeline.filter.ServiceRequestContext;

@Component
@Profile("azure")
public class MSIKeyVaultCredentials extends KeyVaultCredentials {


	final static ScheduledExecutorService EXECUTOR_SERVICE = Executors.newScheduledThreadPool(1);
	final static AppServiceMSICredentials CREDENTIALS = new AppServiceMSICredentials(AzureEnvironment.AZURE);

	@Value("${azure.keyvault.token.uri}")
	private String sbUri ;
	
	/*
	 * public MSIKeyVaultCredentials(String sburi) { this.sbUri = sburi; }
	 */

	@Override
	public Header doAuthenticate(ServiceRequestContext request, Map<String, String> challenge) {
		String accessToken = null;
		String authorization = challenge.get("authorization");
		String resource = challenge.get("resource");
		System.out.println("authorization: "+authorization+" resouce: "+resource);
		try {
			accessToken = getAccessToken(authorization, resource);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 

		return new BasicHeader("Authorization", "Bearer"+ " " + accessToken);
	}

	private String getAccessToken(String authorization, String resource) throws Exception {
        String accesToken = CREDENTIALS.getToken(sbUri);
        return accesToken;   
    }

}
