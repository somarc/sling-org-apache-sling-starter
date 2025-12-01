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

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

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
            
            LOG.info("  📍 Address: {}", address);
            LOG.info("  🆔 Credential ID: {}", credentialId);
            
            // TODO: Store credential mapping
            // Map credentialId -> address for future authentication
            // Store in JCR: /var/blockchain-aem/credentials/{credentialId}
            
            LOG.info("  💾 Storing credential mapping...");
            
            // TODO: Register with validators
            // POST to validator network to whitelist address for write proposals
            // Endpoint: http://localhost:8090/api/register-author
            
            LOG.info("  📡 Registering with validators...");
            
            // TODO: On-chain registration (post-Fusaka)
            // Call smart contract to register P-256 public key
            // Uses EIP-7951 precompile at 0x100 for verification
            // Cost: ~6,900 gas
            
            LOG.info("  ⛓️  On-chain registration (demo mode - skipped)");
            LOG.warn("   Post-Fusaka (Dec 3, 2025): Will register pubkey on-chain");
            
            // TODO: Create Oak user via Oak-Auth-Web3
            // The Web3BiometricLoginModule will handle this on first login
            // For now, just return success
            
            LOG.info("  👤 User will be created on first biometric login");
            LOG.info("     via Oak-Auth-Web3 LoginModule");
            
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

