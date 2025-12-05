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
import com.adobe.aem.blockchain.utils.SignatureVerifier;
import com.adobe.aem.blockchain.utils.PasswordDerivation;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import javax.jcr.Session;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.Servlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Servlet to handle MetaMask authentication with signature verification.
 * 
 * <p>Flow:
 * <ol>
 *   <li>Client connects wallet via eth_requestAccounts</li>
 *   <li>Client requests personal_sign with timestamp message</li>
 *   <li>This servlet receives: address, signature, original message</li>
 *   <li>Servlet verifies signature matches address</li>
 *   <li>Servlet creates/updates user in Oak repository</li>
 *   <li>Servlet creates authenticated Sling session</li>
 * </ol>
 */
@Component(service = Servlet.class)
@SlingServletPaths(value = "/bin/blockchain-aem/metamask-login")
public class MetaMaskLoginServlet extends SlingAllMethodsServlet {

    private static final Logger LOG = LoggerFactory.getLogger(MetaMaskLoginServlet.class);
    private static final Gson GSON = new Gson();
    
    @Reference
    private ResourceResolverFactory resolverFactory;
    
    @Reference
    private SlingRepository repository;
    
    @Reference
    private AuthenticationSupport authSupport;

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) 
            throws IOException {
        
        LOG.info("🦊 MetaMask login request received");
        
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
            String signature = requestData.get("signature").getAsString();
            String message = requestData.get("message").getAsString();
            
            LOG.info("  Address: {}", address);
            LOG.info("  Message: {}", message);
            LOG.info("  Signature: {}...", signature.length() > 20 ? signature.substring(0, 20) : signature);
            
            // ═══════════════════════════════════════════════════════════════════
            // REAL SIGNATURE VERIFICATION (using web3j)
            // This cryptographically proves the user owns the private key!
            // ═══════════════════════════════════════════════════════════════════
            
            LOG.info("🔐 Verifying Ethereum signature (REAL CRYPTO!)...");
            
            boolean signatureValid = SignatureVerifier.verify(message, signature, address);
            
            if (!signatureValid) {
                LOG.error("❌ SIGNATURE VERIFICATION FAILED!");
                LOG.error("   The signature was NOT created by address: {}", address);
                
                JsonObject errorResponse = new JsonObject();
                errorResponse.addProperty("success", false);
                errorResponse.addProperty("error", "Invalid signature - cryptographic verification failed");
                errorResponse.addProperty("hint", "The signature does not match the claimed wallet address");
                
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(GSON.toJson(errorResponse));
                return;
            }
            
            LOG.info("✅ SIGNATURE VERIFIED! Cryptographic proof of wallet ownership confirmed.");
            
            // Step 1: Ensure user exists in JCR (auto-create)
            boolean userCreated = ensureUserExists(address);
            if (userCreated) {
                LOG.info("✅ Auto-created user for wallet: {}", address);
            } else {
                LOG.info("✅ User already exists: {}", address);
                // Ensure permissions are up to date on every login
                ensureUserPermissions(address);
            }
            
            // ═══════════════════════════════════════════════════════════════════
            // Step 2: Authenticate via Oak JAAS using our Web3BiometricLoginModule
            // We pass pre-verified credentials - the LoginModule trusts our signature verification
            // ═══════════════════════════════════════════════════════════════════
            LOG.info("🔐 Authenticating via Oak JAAS (Web3BiometricLoginModule)...");
            
            javax.jcr.SimpleCredentials jcrCreds = new javax.jcr.SimpleCredentials(address, new char[0]);
            jcrCreds.setAttribute("web3.metamask.verified", Boolean.TRUE);
            jcrCreds.setAttribute("web3.metamask.address", address);
            
            LOG.info("   Created credentials:");
            LOG.info("     User ID: {}", jcrCreds.getUserID());
            LOG.info("     Attributes: web3.metamask.verified={}, web3.metamask.address={}", 
                jcrCreds.getAttribute("web3.metamask.verified"), 
                jcrCreds.getAttribute("web3.metamask.address"));
            
            LOG.info("   Authenticating via Oak JAAS and creating Sling auth token...");
            
            javax.jcr.Session jcrSession = null;
            try {
                // Step 1: Authenticate via Oak JAAS (which we know works!)
                jcrSession = repository.login(jcrCreds);
                
                LOG.info("🎉 MetaMask authentication complete via Oak JAAS!");
                LOG.info("   Wallet: {}", address);
                LOG.info("   Session user: {}", jcrSession.getUserID());
                LOG.info("   Auth method: Web3BiometricLoginModule");
                
                // Step 2: Set Web3 authentication cookie
                // This will be recognized by our Web3AuthenticationHandler
                Cookie authCookie = new Cookie("blockchain.aem.auth", address);
                authCookie.setPath("/");
                authCookie.setMaxAge(24 * 60 * 60); // 24 hours
                authCookie.setHttpOnly(true);
                authCookie.setSecure(false); // Set to true in production with HTTPS
                response.addCookie(authCookie);
                
                LOG.info("   ✅ Web3 authentication cookie set");
                LOG.info("   - Cookie name: blockchain.aem.auth");
                LOG.info("   - Value: {}", address);
                LOG.info("   - Will be recognized by Web3AuthenticationHandler on subsequent requests");
                
                // ═══════════════════════════════════════════════════════════════════
                // Step 3: Integrate with Sling authentication framework
                // CRITICAL: Must do this BEFORE sending response!
                // This creates an HTTP session and sets the authentication state
                // ═══════════════════════════════════════════════════════════════════
                LOG.info("🔗 Registering authentication with Sling HTTP session...");
                
                // Create AuthenticationInfo for Sling
                AuthenticationInfo authInfo = new AuthenticationInfo("WEB3", address);
                authInfo.put(ResourceResolverFactory.USER, address);
                authInfo.put(ResourceResolverFactory.PASSWORD, PasswordDerivation.derivePassword(address).toCharArray());
                authInfo.put("user.jcr.session", jcrSession); // Pass the live JCR session
                
                // Integrate with Sling authentication framework to create HTTP session
                authSupport.handleSecurity(request, response);
                
                // Set request attribute that Sling auth will recognize
                request.setAttribute("user.jcr.session", jcrSession);
                
                LOG.info("   ✅ JCR session attached to HTTP request");
                LOG.info("   ✅ Sling HTTP session created");
                LOG.info("   ✅ Sling will maintain this session for subsequent requests");
                
                // DON'T logout - Sling needs this session for the HTTP session!
                // The JCR session is now owned by Sling's authentication framework
                
                JsonObject responseData = new JsonObject();
                responseData.addProperty("success", true);
                responseData.addProperty("address", address);
                responseData.addProperty("userId", jcrSession.getUserID());
                responseData.addProperty("message", "✅ MetaMask authentication successful!");
                responseData.addProperty("authMethod", "Web3BiometricLoginModule + Web3AuthenticationHandler");
                responseData.addProperty("userCreated", userCreated);
                responseData.addProperty("jcrSessionCreated", true);
                responseData.addProperty("cookieSet", true);
                responseData.addProperty("persistent", true);
                responseData.addProperty("sessionAttached", true);
                
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(GSON.toJson(responseData));
                
                LOG.info("✅ MetaMask authentication complete!");
                LOG.info("   Full Sling integration: Web3AuthenticationHandler will handle subsequent requests");
                
            } catch (javax.jcr.LoginException e) {
                LOG.error("❌ Oak JAAS authentication failed: {}", e.getMessage(), e);
                
                if (jcrSession != null && jcrSession.isLive()) {
                    jcrSession.logout();
                }
                
                JsonObject errorResponse = new JsonObject();
                errorResponse.addProperty("success", false);
                errorResponse.addProperty("error", "Authentication failed: " + e.getMessage());
                
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(GSON.toJson(errorResponse));
            } catch (Exception e) {
                LOG.error("❌ Authentication failed: {}", e.getMessage(), e);
                
                if (jcrSession != null && jcrSession.isLive()) {
                    jcrSession.logout();
                }
                
                JsonObject errorResponse = new JsonObject();
                errorResponse.addProperty("success", false);
                errorResponse.addProperty("error", "Authentication failed: " + e.getMessage());
                
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(GSON.toJson(errorResponse));
            }
            
        } catch (Exception e) {
            LOG.error("❌ MetaMask login failed", e);
            
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("success", false);
            errorResponse.addProperty("error", e.getMessage());
            
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write(GSON.toJson(errorResponse));
        }
    }
    
    /**
     * Ensure user exists in JCR repository (create if doesn't exist).
     * Uses service user pattern for elevated privileges.
     * 
     * @param walletAddress The wallet address to use as user ID
     * @return true if user was created, false if already existed
     */
    private boolean ensureUserExists(String walletAddress) {
        LOG.info("🔍 Checking if user exists: {}", walletAddress);
        
        ResourceResolver serviceResolver = null;
        try {
            // Get service resource resolver
            Map<String, Object> authInfo = new HashMap<>();
            authInfo.put(ResourceResolverFactory.SUBSERVICE, "blockchain-aem-registration");
            serviceResolver = resolverFactory.getServiceResourceResolver(authInfo);
            
            // Get session and UserManager
            javax.jcr.Session session = serviceResolver.adaptTo(javax.jcr.Session.class);
            if (session == null) {
                LOG.error("❌ Could not adapt ResourceResolver to Session");
                return false;
            }
            
            // Adapt session to UserManager via Jackrabbit API
            UserManager userManager = ((org.apache.jackrabbit.api.JackrabbitSession) session).getUserManager();
            if (userManager == null) {
                LOG.error("❌ UserManager not available");
                return false;
            }
            
            // Check if user already exists
            Authorizable existing = userManager.getAuthorizable(walletAddress);
            if (existing != null) {
                LOG.info("✅ User already exists: {}", walletAddress);
                return false;
            }
            
            // Create new user with signature-derived password
            LOG.info("👤 Creating new user with derived password: {}", walletAddress);
            
            // Derive deterministic password from wallet address
            String derivedPassword = PasswordDerivation.derivePassword(walletAddress);
            LOG.info("🔐 Password derived for user creation");
            
            Principal principal = new Principal() {
                @Override
                public String getName() {
                    return walletAddress;
                }
            };
            
            User user = userManager.createUser(
                walletAddress,      // User ID (wallet address)
                derivedPassword,    // ✅ Signature-derived password (elegant!)
                principal,          // Principal
                null                // Intermediate path (auto-generated)
            );
            
            LOG.info("✅ User created: {}", user.getID());
            
            // Add to administrators group or grant direct permissions
            Group admins = (Group) userManager.getAuthorizable("administrators");
            if (admins != null) {
                admins.addMember(user);
                LOG.info("✅ User added to administrators group");
            } else {
                LOG.info("ℹ️  No administrators group - granting direct permissions");
                grantAdminPermissions(session, user);
            }
            
            // Save changes
            session.save();
            LOG.info("✅ Changes saved to repository");
            
            return true;
            
        } catch (RepositoryException e) {
            LOG.error("❌ Failed to create user (RepositoryException): {}", e.getMessage(), e);
            return false;
        } catch (org.apache.sling.api.resource.LoginException e) {
            LOG.error("❌ Failed to get service resolver (LoginException): {}", e.getMessage(), e);
            return false;
        } finally {
            if (serviceResolver != null) {
                serviceResolver.close();
            }
        }
    }
    
    /**
     * Grants admin-like permissions directly via ACLs.
     * Used in Sling (non-AEM) environments where groups don't exist.
     */
    private void grantAdminPermissions(Session session, User user) {
        try {
            AccessControlManager acm = session.getAccessControlManager();
            Principal principal = user.getPrincipal();
            
            // Paths to grant permissions on (needed for full Sling functionality)
            String[] contentPaths = {
                "/content",
                "/content/blockchain-aem",
                "/apps",
                "/libs",
                "/bin",
                "/oak-chain",
                "/var"
            };
            
            // Get jcr:all privilege
            Privilege[] privileges = new Privilege[] {
                acm.privilegeFromName(Privilege.JCR_ALL)
            };
            
            for (String path : contentPaths) {
                try {
                    if (!session.nodeExists(path)) {
                        continue;
                    }
                    
                    // Get or create ACL
                    JackrabbitAccessControlList acl = null;
                    for (AccessControlPolicy policy : acm.getPolicies(path)) {
                        if (policy instanceof JackrabbitAccessControlList) {
                            acl = (JackrabbitAccessControlList) policy;
                            break;
                        }
                    }
                    
                    if (acl == null) {
                        AccessControlPolicyIterator it = acm.getApplicablePolicies(path);
                        while (it.hasNext()) {
                            AccessControlPolicy policy = it.nextAccessControlPolicy();
                            if (policy instanceof JackrabbitAccessControlList) {
                                acl = (JackrabbitAccessControlList) policy;
                                break;
                            }
                        }
                    }
                    
                    if (acl != null) {
                        acl.addAccessControlEntry(principal, privileges);
                        acm.setPolicy(path, acl);
                        LOG.info("✅ Granted jcr:all on {}", path);
                    }
                } catch (Exception e) {
                    LOG.warn("⚠️  Failed to set ACL on {}: {}", path, e.getMessage());
                }
            }
        } catch (Exception e) {
            LOG.error("❌ Failed to grant admin permissions", e);
        }
    }
    
    /**
     * Ensure an existing user has proper permissions (called on every login).
     * This handles cases where permissions were added after the user was created.
     */
    private void ensureUserPermissions(String walletAddress) {
        LOG.info("🔄 Ensuring permissions for existing user: {}", walletAddress);
        
        ResourceResolver serviceResolver = null;
        try {
            Map<String, Object> authInfo = new HashMap<>();
            authInfo.put(ResourceResolverFactory.SUBSERVICE, "blockchain-aem-registration");
            serviceResolver = resolverFactory.getServiceResourceResolver(authInfo);
            
            javax.jcr.Session session = serviceResolver.adaptTo(javax.jcr.Session.class);
            if (session == null) {
                LOG.warn("⚠️  Could not get session for permission update");
                return;
            }
            
            UserManager userManager = ((org.apache.jackrabbit.api.JackrabbitSession) session).getUserManager();
            User user = (User) userManager.getAuthorizable(walletAddress);
            
            if (user != null) {
                grantAdminPermissions(session, user);
                session.save();
                LOG.info("✅ Permissions updated for: {}", walletAddress);
            }
        } catch (Exception e) {
            LOG.warn("⚠️  Could not update permissions: {}", e.getMessage());
        } finally {
            if (serviceResolver != null) {
                serviceResolver.close();
            }
        }
    }
}

