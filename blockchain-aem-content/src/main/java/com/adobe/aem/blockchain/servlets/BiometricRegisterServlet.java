/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.adobe.aem.blockchain.servlets;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Node;
import javax.jcr.Session;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;

/**
 * Servlet to handle biometric wallet registration (EIP-7951 P-256 flow).
 * 
 * <p>Post-Fusaka (Dec 3, 2025) flow:
 * <ol>
 *   <li>Client creates WebAuthn credential (P-256 keypair in hardware)</li>
 *   <li>Client derives Ethereum address from public key</li>
 *   <li>This servlet receives: address, credentialId, pubKey</li>
 *   <li>Servlet stores credential mapping</li>
 *   <li>Servlet registers with validators (optional)</li>
 *   <li>Servlet triggers Oak-Auth-Web3 user creation</li>
 * </ol>
 * 
 * <p>Integration points:
 * <ul>
 *   <li>Oak-Auth-Web3: Creates user in /rep:security/rep:authorizables/rep:users/</li>
 *   <li>Validator Network: Whitelists address for write proposals</li>
 *   <li>Smart Contract: Registers pubkey on-chain (post-Fusaka)</li>
 * </ul>
 */
@Component(service = Servlet.class)
@SlingServletPaths(value = "/bin/blockchain-aem/biometric-register")
public class BiometricRegisterServlet extends SlingAllMethodsServlet {

    private static final Logger LOG = LoggerFactory.getLogger(BiometricRegisterServlet.class);
    private static final Gson GSON = new Gson();

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) 
            throws IOException {
        
        LOG.info("🔐 Biometric wallet registration request received");
        
        try {
            // Parse request body
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = request.getReader()) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }
            
            JsonObject requestData = GSON.fromJson(sb.toString(), JsonObject.class);
            String address = requestData.get("address").getAsString();
            String credentialId = requestData.get("credentialId").getAsString();
            
            // Get public key - it can be an array of bytes or a base64 string
            String publicKeyBase64 = null;
            if (requestData.has("pubKey")) {
                if (requestData.get("pubKey").isJsonArray()) {
                    // Array of byte values - convert to base64
                    byte[] pubKeyBytes = new byte[requestData.getAsJsonArray("pubKey").size()];
                    for (int i = 0; i < pubKeyBytes.length; i++) {
                        pubKeyBytes[i] = requestData.getAsJsonArray("pubKey").get(i).getAsByte();
                    }
                    publicKeyBase64 = Base64.getEncoder().encodeToString(pubKeyBytes);
                } else {
                    publicKeyBase64 = requestData.get("pubKey").getAsString();
                }
            }
            
            LOG.info("  📍 Address: {}", address);
            LOG.info("  🆔 Credential ID: {}", credentialId);
            LOG.info("  🔑 Public Key: {} bytes", publicKeyBase64 != null ? Base64.getDecoder().decode(publicKeyBase64).length : 0);
            
            // Store credential mapping in JCR: /var/blockchain-aem/credentials/{address}
            Session session = request.getResourceResolver().adaptTo(Session.class);
            if (session != null) {
                try {
                    // Create /var/blockchain-aem/credentials path if it doesn't exist
                    Node varNode = session.getRootNode();
                    if (!varNode.hasNode("var")) {
                        varNode = varNode.addNode("var", "sling:Folder");
                    } else {
                        varNode = varNode.getNode("var");
                    }
                    
                    Node blockchainNode;
                    if (!varNode.hasNode("blockchain-aem")) {
                        blockchainNode = varNode.addNode("blockchain-aem", "sling:Folder");
                    } else {
                        blockchainNode = varNode.getNode("blockchain-aem");
                    }
                    
                    Node credentialsNode;
                    if (!blockchainNode.hasNode("credentials")) {
                        credentialsNode = blockchainNode.addNode("credentials", "sling:Folder");
                    } else {
                        credentialsNode = blockchainNode.getNode("credentials");
                    }
                    
                    // Store credential data under wallet address (sanitized for JCR node name)
                    String nodeName = address.replace("0x", "wallet_");
                    Node credentialNode;
                    if (credentialsNode.hasNode(nodeName)) {
                        credentialNode = credentialsNode.getNode(nodeName);
                    } else {
                        credentialNode = credentialsNode.addNode(nodeName, "nt:unstructured");
                    }
                    
                    credentialNode.setProperty("walletAddress", address);
                    credentialNode.setProperty("credentialId", credentialId);
                    if (publicKeyBase64 != null) {
                        credentialNode.setProperty("publicKey", publicKeyBase64);
                    }
                    credentialNode.setProperty("registeredAt", System.currentTimeMillis());
                    
                    session.save();
                    LOG.info("  💾 Credential stored at /var/blockchain-aem/credentials/{}", nodeName);
                    
                } catch (Exception e) {
                    LOG.warn("  ⚠️ Could not store credential in JCR: {}", e.getMessage());
                }
            }
            
            LOG.info("  📡 Validator registration (demo mode - skipped)");
            LOG.info("  ⛓️  On-chain registration (demo mode - skipped)");
            LOG.info("  👤 User will be created on first biometric login via Oak-Auth-Web3");
            
            JsonObject responseData = new JsonObject();
            responseData.addProperty("success", true);
            responseData.addProperty("address", address);
            responseData.addProperty("message", "Biometric wallet registered successfully");
            responseData.addProperty("nextStep", "Sign in with your biometric to create Oak user");
            
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write(GSON.toJson(responseData));
            
            LOG.info("✅ Biometric wallet registration successful");
            LOG.info("   User can now sign in with Face ID/Touch ID");
            
        } catch (Exception e) {
            LOG.error("❌ Biometric wallet registration failed", e);
            
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("success", false);
            errorResponse.addProperty("error", e.getMessage());
            errorResponse.addProperty("message", "Registration failed. Please try again.");
            
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write(GSON.toJson(errorResponse));
        }
    }
}

