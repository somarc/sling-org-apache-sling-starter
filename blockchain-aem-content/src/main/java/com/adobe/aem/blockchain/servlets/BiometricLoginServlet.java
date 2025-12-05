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

import com.adobe.aem.blockchain.utils.PasswordDerivation;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.servlet.Servlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;

/**
 * Servlet for biometric authentication via Web3BiometricLoginModule.
 * 
 * This servlet:
 * 1. Receives biometric assertion data from the client (WebAuthn)
 * 2. Creates a Web3BiometricCredentials object
 * 3. Uses JCR Repository.login() to invoke Oak's JAAS chain
 * 4. The Web3BiometricLoginModule validates the credentials and creates a session
 * 5. Returns success/failure to the client
 */
@Component(
    service = {Servlet.class},
    property = {
        "sling.servlet.methods=POST",
        "sling.servlet.paths=/bin/blockchain-aem/biometric-login",
        "sling.servlet.extensions=json"
    }
)
public class BiometricLoginServlet extends SlingAllMethodsServlet {
    
    private static final Logger LOG = LoggerFactory.getLogger(BiometricLoginServlet.class);
    private static final Gson GSON = new Gson();
    
    @Reference
    private SlingRepository repository;
    
    @Reference
    private AuthenticationSupport authSupport;
    
    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) 
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            // Parse request body
            BufferedReader reader = request.getReader();
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            
            JsonObject requestData = GSON.fromJson(sb.toString(), JsonObject.class);
            
            // Extract biometric assertion data
            String walletAddress = requestData.get("address").getAsString();
            String credentialId = requestData.get("credentialId").getAsString();
            String signature = requestData.get("signature").getAsString();
            String challenge = requestData.get("challenge").getAsString();
            String publicKey = requestData.get("publicKey").getAsString();
            
            LOG.info("🔐 Biometric login attempt for wallet: {}", walletAddress);
            LOG.info("📍 Credential ID: {}", credentialId);
            
            // Create Web3BiometricCredentials using SimpleCredentials as a carrier
            // The Web3BiometricLoginModule will recognize this pattern
            SimpleCredentials jcrCreds = new SimpleCredentials(walletAddress, new char[0]);
            
            // Add biometric data as attributes (the LoginModule will extract these)
            jcrCreds.setAttribute("web3.biometric.credentialId", credentialId);
            jcrCreds.setAttribute("web3.biometric.publicKey", Base64.getDecoder().decode(publicKey));
            jcrCreds.setAttribute("web3.biometric.signature", Base64.getDecoder().decode(signature));
            jcrCreds.setAttribute("web3.biometric.challenge", Base64.getDecoder().decode(challenge));
            jcrCreds.setAttribute("web3.biometric.walletAddress", walletAddress);
            
            // Attempt login using injected SlingRepository - this triggers the Oak JAAS chain
            // including Web3BiometricLoginModule
            Session session = null;
            try {
                session = repository.login(jcrCreds);
                
                LOG.info("✅ Biometric authentication successful for: {}", walletAddress);
                LOG.info("📂 Session user ID: {}", session.getUserID());
                
                // ═══════════════════════════════════════════════════════════════════
                // CRITICAL: Integrate with Sling authentication framework
                // This creates an HTTP session and maintains authentication state
                // ═══════════════════════════════════════════════════════════════════
                LOG.info("🔗 Registering authentication with Sling HTTP session...");
                
                // Create AuthenticationInfo for Sling
                AuthenticationInfo authInfo = new AuthenticationInfo("WEB3_BIOMETRIC", walletAddress);
                authInfo.put(ResourceResolverFactory.USER, walletAddress);
                authInfo.put(ResourceResolverFactory.PASSWORD, PasswordDerivation.derivePassword(walletAddress).toCharArray());
                authInfo.put("user.jcr.session", session); // Pass the live JCR session
                
                // Integrate with Sling authentication framework to create HTTP session
                authSupport.handleSecurity(request, response);
                
                // Set request attribute that Sling auth will recognize
                request.setAttribute("user.jcr.session", session);
                
                LOG.info("   ✅ JCR session attached to HTTP request");
                LOG.info("   ✅ Sling HTTP session created");
                LOG.info("   ✅ Sling will maintain this session for subsequent requests");
                
                // ✅ Create and set the authentication cookie (matching MetaMask pattern)
                Cookie authCookie = new Cookie("blockchain.aem.auth", walletAddress);
                authCookie.setPath("/");
                authCookie.setMaxAge(24 * 60 * 60); // 24 hours
                authCookie.setHttpOnly(true);
                authCookie.setSecure(request.isSecure());
                response.addCookie(authCookie);
                
                LOG.info("   ✅ Web3 authentication cookie set for biometric login");
                LOG.info("   - Cookie name: blockchain.aem.auth");
                LOG.info("   - Value: {}", walletAddress);
                LOG.info("   - Will be recognized by Web3AuthenticationHandler on subsequent requests");
                
                // Success response (Sling will handle session management)
                JsonObject successResponse = new JsonObject();
                successResponse.addProperty("success", true);
                successResponse.addProperty("message", "Biometric authentication successful");
                successResponse.addProperty("userId", session.getUserID());
                successResponse.addProperty("walletAddress", walletAddress);
                successResponse.addProperty("sessionCreated", true);
                successResponse.addProperty("persistent", true);
                
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(GSON.toJson(successResponse));
                
            } catch (Exception e) {
                LOG.error("❌ Biometric authentication failed for {}: {}", walletAddress, e.getMessage());
                
                // Authentication failed
                JsonObject errorResponse = new JsonObject();
                errorResponse.addProperty("success", false);
                errorResponse.addProperty("error", "Authentication failed: " + e.getMessage());
                
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(GSON.toJson(errorResponse));
                
            } finally {
                // Don't logout the session - Sling needs it for the HTTP session!
                // The JCR session is now owned by Sling's authentication framework
                if (session != null && session.isLive()) {
                    LOG.debug("   JCR session kept alive for Sling HTTP session");
                }
            }
            
        } catch (Exception e) {
            LOG.error("❌ Error processing biometric login request", e);
            
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("success", false);
            errorResponse.addProperty("error", "Server error: " + e.getMessage());
            
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write(GSON.toJson(errorResponse));
        }
    }
}

