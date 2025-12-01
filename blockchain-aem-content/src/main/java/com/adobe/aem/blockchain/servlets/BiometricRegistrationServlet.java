package com.adobe.aem.blockchain.servlets;

import com.adobe.aem.blockchain.config.BlockchainConfigService;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Servlet for registering biometric passkeys with ValidatorPaymentV4 contract.
 * 
 * <p>Flow:
 * 1. POST with wallet signature proving ownership
 * 2. Forward credentialId + publicKey to validator
 * 3. Validator calls ValidatorPaymentV4.registerBiometric()
 * 4. Store credentialId in Oak repository for this user
 * 
 * @see <a href="https://w3c.github.io/webauthn/">WebAuthn Specification</a>
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain-aem/register-biometric",
        "sling.servlet.methods=POST"
    }
)
public class BiometricRegistrationServlet extends SlingAllMethodsServlet {
    
    private static final Logger LOG = LoggerFactory.getLogger(BiometricRegistrationServlet.class);
    private static final Gson GSON = new Gson();
    
    @Reference
    private transient BlockchainConfigService configService;
    
    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            // Parse request
            JsonObject requestBody = parseRequestBody(request);
            
            String walletAddress = requestBody.get("walletAddress").getAsString();
            String credentialId = requestBody.get("credentialId").getAsString();
            String publicKeyBase64 = requestBody.get("publicKey").getAsString();
            String deviceName = requestBody.has("deviceName") 
                ? requestBody.get("deviceName").getAsString() 
                : "Unknown Device";
            String walletSignature = requestBody.get("walletSignature").getAsString();
            
            LOG.info("🔐 Biometric registration request: wallet={}, device={}", 
                    walletAddress, deviceName);
            
            // Validate inputs
            if (!isValidEthereumAddress(walletAddress)) {
                sendError(response, 400, "Invalid wallet address");
                return;
            }
            
            byte[] publicKey = Base64.getDecoder().decode(publicKeyBase64);
            if (publicKey.length != 65 || publicKey[0] != 0x04) {
                sendError(response, 400, "Invalid P-256 public key (must be 65 bytes, uncompressed)");
                return;
            }
            
            // Forward to validator
            String validatorUrl = configService.getValidatorUrl();
            JsonObject validatorRequest = new JsonObject();
            validatorRequest.addProperty("walletAddress", walletAddress);
            validatorRequest.addProperty("credentialId", credentialId);
            validatorRequest.addProperty("publicKey", publicKeyBase64);
            validatorRequest.addProperty("deviceName", deviceName);
            validatorRequest.addProperty("walletSignature", walletSignature);
            
            String validatorResponseBody = postToValidator(
                validatorUrl + "/v2/register-biometric",
                validatorRequest.toString()
            );
            
            // Success response
            JsonObject successResponse = new JsonObject();
            successResponse.addProperty("success", true);
            successResponse.addProperty("message", "Biometric registered successfully");
            successResponse.addProperty("walletAddress", walletAddress);
            successResponse.addProperty("credentialId", credentialId);
            successResponse.addProperty("deviceName", deviceName);
            successResponse.add("validatorResponse", GSON.fromJson(validatorResponseBody, JsonObject.class));
            
            response.getWriter().write(GSON.toJson(successResponse));
            
            LOG.info("✅ Biometric registration successful: wallet={}, credentialId={}", 
                    walletAddress, credentialId);
            
        } catch (Exception e) {
            LOG.error("❌ Biometric registration error", e);
            sendError(response, 500, "Registration error: " + e.getMessage());
        }
    }
    
    /**
     * POST to validator endpoint
     */
    private String postToValidator(String url, String jsonBody) throws IOException {
        URL validatorUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) validatorUrl.openConnection();
        
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            
            // Send request
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            
            // Read response
            int responseCode = conn.getResponseCode();
            if (responseCode != 200 && responseCode != 202) {
                throw new IOException("Validator returned " + responseCode);
            }
            
            try (BufferedReader br = new BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
                return response.toString();
            }
        } finally {
            conn.disconnect();
        }
    }
    
    private JsonObject parseRequestBody(SlingHttpServletRequest request) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        return GSON.fromJson(sb.toString(), JsonObject.class);
    }
    
    private boolean isValidEthereumAddress(String address) {
        return address != null && address.matches("^0x[0-9a-fA-F]{40}$");
    }
    
    private void sendError(SlingHttpServletResponse response, int statusCode, String message) 
            throws IOException {
        response.setStatus(statusCode);
        JsonObject error = new JsonObject();
        error.addProperty("success", false);
        error.addProperty("error", message);
        response.getWriter().write(GSON.toJson(error));
    }
}

