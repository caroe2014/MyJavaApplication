package com.aa.opshub.azure.rsa;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.KeyVaultClientService;
import com.microsoft.azure.keyvault.KeyVaultConfiguration;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyEncryptionAlgorithm;
import com.microsoft.windowsazure.Configuration;

@Component
public class AzureRSAUtils {

	@Value("${azure.keyvault.token.uri}")
	private String sbUri;
	
	@Value("${azure.keyvault.rsa.uri}")
	private String  rsaKeyUrl;
	
	@Autowired
	KeyVaultCredentials keyVaultCredentials;
	
	public String encryptKey(byte[] aesKey) throws InterruptedException, ExecutionException {
		Configuration config = KeyVaultConfiguration.configure(null, keyVaultCredentials);
		KeyVaultClient kvc = KeyVaultClientService.create(config);
		Future<KeyOperationResult> result = kvc.encryptAsync(rsaKeyUrl, JsonWebKeyEncryptionAlgorithm.RSAOAEP,
				aesKey);
		KeyOperationResult keyoperationResult = result.get();
		return Base64.encodeBase64String(keyoperationResult.getResult());
	}
	
	public byte[] decryptKey(String aesKey) throws InterruptedException, ExecutionException {
		Configuration config = KeyVaultConfiguration.configure(null, keyVaultCredentials);
		KeyVaultClient kvc = KeyVaultClientService.create(config);
		Future<KeyOperationResult> result = kvc.decryptAsync(rsaKeyUrl, JsonWebKeyEncryptionAlgorithm.RSAOAEP,
				Base64.decodeBase64(aesKey));
		KeyOperationResult keyoperationResult = result.get();
		return keyoperationResult.getResult();
	}
	
	
	/*
	 * public String start(String sbUri, byte[] byteText) throws Exception {
	 * 
	 * //String textToEncrypt = "This is a long text to ecrypt with rsa";
	 * 
	 * String keyIdentifier =
	 * "https://opshub-test-43-kv.vault.azure.net/keys/rsakey/";
	 * 
	 * KeyVaultCredentials kvCred = new MSIKeyVaultCredentials(sbUri); Configuration
	 * config = KeyVaultConfiguration.configure(null, kvCred); KeyVaultClient kvc =
	 * KeyVaultClientService.create(config);
	 * 
	 * //byte[] byteText = textToEncrypt.getBytes("UTF-16");
	 * Future<KeyOperationResult> result = kvc.encryptAsync(keyIdentifier,
	 * JsonWebKeyEncryptionAlgorithm.RSAOAEP, byteText); KeyOperationResult
	 * keyoperationResult = result.get(); System.out.println("KeyOperationResult: "
	 * + keyoperationResult); String encryptedEncodeBase64String =
	 * Base64.encodeBase64String(keyoperationResult.getResult());
	 * System.out.println("Encrypted(base64): " + encryptedEncodeBase64String); //
	 * Decryption result = kvc.decryptAsync(keyIdentifier, "RSA-OAEP",
	 * keyoperationResult.getResult()); String decryptedResult = new
	 * String(result.get().getResult(), "UTF-16"); System.out.println("Decpryted: "
	 * + decryptedResult);
	 * 
	 * return encryptedEncodeBase64String+" | "+decryptedResult;
	 * 
	 * 
	 * }
	 */
	
}
