package com.mysticplanets.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.http.*;

import org.springframework.web.client.RestTemplate;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import com.apple.itunes.storekit.client.APIException;
import com.apple.itunes.storekit.client.AppStoreServerAPIClient;
import com.apple.itunes.storekit.model.Environment;
import com.apple.itunes.storekit.model.HistoryResponse;

import com.apple.itunes.storekit.model.TransactionHistoryRequest;
import com.apple.itunes.storekit.model.TransactionInfoResponse;
import com.apple.itunes.storekit.model.NotificationHistoryResponse;
import com.apple.itunes.storekit.model.NotificationHistoryRequest;

import com.apple.itunes.storekit.model.ResponseBodyV2DecodedPayload;
import com.apple.itunes.storekit.model.SendTestNotificationResponse;
import com.apple.itunes.storekit.verification.SignedDataVerifier;

import com.apple.itunes.storekit.offers.PromotionalOfferSignatureCreator;

import java.nio.file.Files;
import java.nio.file.Path;

//@Transactional(readOnly = true)
public class AppleAPIService {
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
        //createJWTToken();
		String issuerId = "69a6de82-111e-47e3-e053-5b8c7c11a4d1";
        String keyId = "FZL9Y9458N";
        String bundleId = "com.mysticplanets";
        Path filePath = Path.of("SubscriptionKey_FZL9Y9458N.p8");
        String encodedKey = Files.readString(filePath);
        Environment environment = Environment.SANDBOX;
        System.out.println(environment);
        
        
        
        // Environment environment = Environment.PRODUCTION;

        AppStoreServerAPIClient client = new AppStoreServerAPIClient(encodedKey, keyId, issuerId, bundleId, environment);
        
        
        //String appReceipt = "MI...";
        //ReceiptUtility receiptUtil = new ReceiptUtility();
        //String transactionId = receiptUtil.extractTransactionIdFromAppReceipt(appReceipt);
        
        try {
            SendTestNotificationResponse response = client.requestTestNotification();
            System.out.println(response);
        } catch (APIException | IOException e) {
            e.printStackTrace();
        }
        
        String transactionId = "6474433543"; //???????????????????????????
        if (transactionId != null) {
            TransactionHistoryRequest request = new TransactionHistoryRequest()
                    .sort(TransactionHistoryRequest.Order.ASCENDING)
                    .revoked(false)
                    .productTypes(List.of(TransactionHistoryRequest.ProductType.AUTO_RENEWABLE));
            HistoryResponse response = null;
            List<String> transactions = new LinkedList<>();
            do {
                String revision = response != null ? response.getRevision() : null;
                try {
                	response = client.getTransactionHistory(transactionId, revision, request);
                //response = client.getTransactionHistory(transactionId, revision, request);
                	transactions.addAll(response.getSignedTransactions());
                } catch (APIException | IOException e) {
                    e.printStackTrace();
                }
            } while (response.getHasMore());
            System.out.println(transactions);
        } 

    }

    public static String createJWTToken() {

        try (PemReader pemReader = new PemReader(new FileReader("AuthKey_4RX68T8XAM.p8"))) {

            //try (PemReader pemReader = new PemReader(new FileReader("AuthKey_5QRFG5C59Q.p8"))) {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PemObject pemObj = pemReader.readPemObject();
            byte[] content = pemObj.getContent();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            String token = JWT.create()
                    .withKeyId("4RX68T8XAM")
                    .withIssuer("69a6de82-111e-47e3-e053-5b8c7c11a4d1")
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 1199L))
                   // .withClaim("scope", Collections.singletonList("GET /v1/apps"))
                    .withClaim("scope", Collections.singletonList("GET /v1/apps"))
                    .withJWTId(UUID.randomUUID().toString())
                    .withAudience("appstoreconnect-v1")
                    .sign(Algorithm.ECDSA256(privateKey));

            System.out.println("JWT token: " + token);

            // Create headers with Authorization
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            System.out.println("headers: " + headers);

            // Create HttpEntity with headers
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // Make GET request using RestTemplate
            ResponseEntity<String> response = new RestTemplate().exchange(
                    "https://api.appstoreconnect.apple.com/v1/apps",
                    HttpMethod.GET, entity, String.class);

            // Handle the response
            if (response.getStatusCode() == HttpStatus.OK) {
                String responseBody = response.getBody();
                System.out.println("Response: " + responseBody);
                return responseBody;
            } else {
                System.out.println("Error: " + response.getStatusCodeValue());
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        return null ;

    }
}
