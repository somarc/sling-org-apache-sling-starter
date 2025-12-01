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
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/**
 * Servlet for submitting write proposals with biometric authentication.
 * 
 * <p>Two-phase flow:
 * Phase 1 (GET): Generate challenge for WebAuthn signing
 * Phase 2 (POST): Submit signed proposal with P-256 signature
 * 
 * <p>This servlet handles the "WOW" moment: Face ID → Oak-chain write!
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain-aem/propose-write-biometric",
        "sling.servlet.methods=GET,POST"
    }
)
public class BiometricWriteProposalServlet extends SlingAllMethodsServlet {
    
    private static final Logger LOG = LoggerFactory.getLogger(BiometricWriteProposalServlet.class);
    private static final Gson GSON = new Gson();
    
    @Reference
    private transient BlockchainConfigService configService;
    
    /**
     * Phase 1: Generate challenge for WebAuthn signing.
     * Called before triggering Face ID/Touch ID.
     */
    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            // Get authenticated user (via Oak-Auth-Web3 or ResourceResolver)
            String walletAddress = request.getResourceResolver().getUserID();
            
            if (walletAddress == null || !isValidEthereumAddress(walletAddress)) {
                sendError(response, 401, "Not authenticated with wallet");
                return;
            }
            
            // Parse proposal parameters
            String path = request.getParameter("path");
            String content = request.getParameter("content");
            
            if (path == null || content == null) {
                sendError(response, 400, "Missing path or content");
                return;
            }
            
            // Generate challenge
            String proposalId = UUID.randomUUID().toString();
            long timestamp = System.currentTimeMillis();
            
            String challengeMessage = String.format(
                "Blockchain AEM Write Proposal\n" +
                "Path: %s\n" +
                "Wallet: %s\n" +
                "Timestamp: %d\n" +
                "Proposal ID: %s",
                path, walletAddress, timestamp, proposalId
            );
            
            byte[] challengeBytes = challengeMessage.getBytes(StandardCharsets.UTF_8);
            String challengeBase64 = Base64.getEncoder().encodeToString(challengeBytes);
            
            // Store challenge in session (replay protection)
            request.getSession().setAttribute("biometric_challenge_" + proposalId, challengeBase64);
            request.getSession().setAttribute("biometric_challenge_ts_" + proposalId, timestamp);
            
            // Return challenge to client
            JsonObject challengeResponse = new JsonObject();
            challengeResponse.addProperty("challenge", challengeBase64);
            challengeResponse.addProperty("walletAddress", walletAddress);
            challengeResponse.addProperty("proposalId", proposalId);
            challengeResponse.addProperty("path", path);
            challengeResponse.addProperty("timestamp", timestamp);
            
            response.getWriter().write(GSON.toJson(challengeResponse));
            
            LOG.info("📝 Generated biometric challenge: wallet={}, proposalId={}, path={}", 
                    walletAddress, proposalId, path);
            
        } catch (Exception e) {
            LOG.error("❌ Challenge generation error", e);
            sendError(response, 500, "Challenge generation error: " + e.getMessage());
        }
    }
    
    /**
     * Phase 2: Submit signed proposal with P-256 signature.
     * Called after user scans Face ID/Touch ID.
     */
    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            // Parse signed proposal
            JsonObject requestBody = parseRequestBody(request);
            
            String proposalId = requestBody.get("proposalId").getAsString();
            String walletAddress = requestBody.get("walletAddress").getAsString();
            String credentialId = requestBody.get("credentialId").getAsString();
            String signatureBase64 = requestBody.get("signature").getAsString();
            String publicKeyBase64 = requestBody.get("publicKey").getAsString();
            String challengeBase64 = requestBody.get("challenge").getAsString();
            String path = requestBody.get("path").getAsString();
            String content = requestBody.get("content").getAsString();
            String segmentId = requestBody.has("segmentId") 
                ? requestBody.get("segmentId").getAsString()
                : generateSegmentId(content);
            
            LOG.info("🔐 Biometric write proposal: wallet={}, path={}, proposalId={}", 
                    walletAddress, path, proposalId);
            
            // Verify challenge (replay protection)
            String storedChallenge = (String) request.getSession()
                .getAttribute("biometric_challenge_" + proposalId);
            
            if (storedChallenge == null || !storedChallenge.equals(challengeBase64)) {
                sendError(response, 403, "Invalid or expired challenge");
                return;
            }
            
            Long challengeTimestamp = (Long) request.getSession()
                .getAttribute("biometric_challenge_ts_" + proposalId);
            
            if (challengeTimestamp == null || 
                System.currentTimeMillis() - challengeTimestamp > 60000) {
                sendError(response, 403, "Challenge expired (60s timeout)");
                return;
            }
            
            // Clear challenge (one-time use)
            request.getSession().removeAttribute("biometric_challenge_" + proposalId);
            request.getSession().removeAttribute("biometric_challenge_ts_" + proposalId);
            
            // Submit to validator
            String validatorUrl = configService.getValidatorUrl();
            
            JsonObject validatorRequest = new JsonObject();
            validatorRequest.addProperty("walletAddress", walletAddress);
            validatorRequest.addProperty("credentialId", credentialId);
            validatorRequest.addProperty("signature", signatureBase64);
            validatorRequest.addProperty("publicKey", publicKeyBase64);
            validatorRequest.addProperty("challenge", challengeBase64);
            validatorRequest.addProperty("path", path);
            validatorRequest.addProperty("content", content);
            validatorRequest.addProperty("segmentId", segmentId);
            validatorRequest.addProperty("proposalId", proposalId);
            validatorRequest.addProperty("tier", requestBody.has("tier") 
                ? requestBody.get("tier").getAsInt() 
                : 0); // Default to STANDARD
            
            String validatorResponseBody = postToValidator(
                validatorUrl + "/v2/propose-write-biometric",
                validatorRequest.toString()
            );
            
            // Success response
            JsonObject successResponse = GSON.fromJson(validatorResponseBody, JsonObject.class);
            successResponse.addProperty("success", true);
            successResponse.addProperty("message", "Biometric write proposal submitted");
            successResponse.addProperty("signatureType", "biometric");
            
            response.getWriter().write(GSON.toJson(successResponse));
            
            LOG.info("✅ Biometric write proposal submitted: wallet={}, proposalId={}, path={}", 
                    walletAddress, proposalId, path);
            
        } catch (Exception e) {
            LOG.error("❌ Biometric write proposal error", e);
            sendError(response, 500, "Proposal error: " + e.getMessage());
        }
    }
    
    private String generateSegmentId(String content) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
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
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(30000);
            
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

