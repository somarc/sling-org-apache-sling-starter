/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.adobe.aem.blockchain.servlets;

import org.apache.jackrabbit.oak.segment.http.wallet.SlingAuthorWalletService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Servlet that signs write proposals with the Sling Author's Ethereum wallet.
 * 
 * This is the Java equivalent of what the 30-minute econ script does in Python:
 * - Gets Sling Author's wallet (content owner)
 * - Creates a proposal JSON
 * - Signs it with the Sling Author's private key
 * - Returns signature + public key for validator submission
 * 
 * Three-Address Model:
 * - Content Owner (Sling Author): This wallet - signs the proposal
 * - Payer (MetaMask User): Pays for the transaction (separate step)
 * - Validators: Verify signature and replicate content
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain/sign-proposal",
        "sling.servlet.methods=POST"
    }
)
public class SignProposalServlet extends SlingAllMethodsServlet {

    private static final Logger log = LoggerFactory.getLogger(SignProposalServlet.class);

    @Reference
    private SlingAuthorWalletService walletService;

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Check if wallet service is available
        if (walletService == null || !walletService.isAvailable()) {
            log.error("Sling Author wallet service not available");
            response.setStatus(503);
            response.getWriter().write(
                "{\"error\":\"Wallet service not available\"}"
            );
            return;
        }

        try {
            // 1. Get parameters from frontend
            String proposalId = request.getParameter("proposalId");
            String path = request.getParameter("path");
            String title = request.getParameter("title");
            String content = request.getParameter("content");
            String organization = request.getParameter("organization");
            String tier = request.getParameter("tier");
            
            // Validate required parameters
            if (proposalId == null || path == null || title == null || 
                content == null || organization == null || tier == null) {
                response.setStatus(400);
                response.getWriter().write(
                    "{\"error\":\"Missing required parameters\"}"
                );
                return;
            }

            // 2. Get Sling Author's wallet info
            String contentOwner = walletService.getWalletAddress();
            String publicKey = walletService.getPublicKeyHex();
            
            log.info("📝 Creating proposal:");
            log.info("  ID: {}", proposalId);
            log.info("  Content Owner (Sling Author): {}", contentOwner);
            log.info("  Path: {}", path);
            log.info("  Tier: {}", tier);

            // 3. Calculate content hash (SHA-256)
            String contentHash = calculateContentHash(content);

            // 4. Create proposal JSON (same format as Python script)
            String proposalJson = String.format(
                "{\"proposalId\":\"%s\",\"contentOwner\":\"%s\",\"path\":\"%s\"," +
                "\"title\":\"%s\",\"content\":\"%s\",\"organization\":\"%s\"," +
                "\"tier\":%s,\"contentHash\":\"%s\"}",
                proposalId, contentOwner, path, 
                escapeJson(title), escapeJson(content), organization,
                tier, contentHash
            );

            log.info("📋 Proposal JSON: {}", proposalJson);

            // 5. Sign proposal with Sling Author's private key
            String signature = walletService.sign(proposalJson);
            
            if (signature == null) {
                log.error("Failed to sign proposal");
                response.setStatus(500);
                response.getWriter().write(
                    "{\"error\":\"Failed to sign proposal\"}"
                );
                return;
            }

            log.info("✅ Proposal signed successfully");
            log.info("  Signature: {}...", signature.substring(0, Math.min(20, signature.length())));

            // 6. Build response
            String responseJson = String.format(
                "{\"success\":true," +
                "\"proposal\":%s," +
                "\"signature\":\"%s\"," +
                "\"publicKey\":\"%s\"," +
                "\"contentOwner\":\"%s\"," +
                "\"contentHash\":\"%s\"}",
                proposalJson, signature, publicKey, contentOwner, contentHash
            );

            response.getWriter().write(responseJson);
            
        } catch (Exception e) {
            log.error("Failed to sign proposal", e);
            response.setStatus(500);
            response.getWriter().write(
                String.format("{\"error\":\"Internal error: %s\"}", e.getMessage())
            );
        }
    }

    /**
     * Calculate SHA-256 hash of content (same as Python script)
     */
    private String calculateContentHash(String content) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
        return "0x" + bytesToHex(hash);
    }

    /**
     * Convert byte array to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Escape JSON special characters
     */
    private String escapeJson(String str) {
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}

