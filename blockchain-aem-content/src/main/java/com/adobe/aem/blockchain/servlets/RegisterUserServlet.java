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
import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;

import javax.jcr.Session;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.Principal;

/**
 * Servlet to register new users with wallet addresses.
 * 
 * <p>Creates users in Oak repository at /rep:security/rep:authorizables/rep:users/
 * with wallet address as user ID, and adds them to administrators group for demo purposes.
 * 
 * <p>This servlet is anonymous-accessible to allow user self-registration.
 * In production, you would want additional validation (on-chain verification, captcha, etc.)
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.auth.requirements=-/bin/blockchain-aem/register-user"  // Anonymous access
    }
)
@SlingServletPaths(value = "/bin/blockchain-aem/register-user")
public class RegisterUserServlet extends SlingAllMethodsServlet {

    private static final Logger LOG = LoggerFactory.getLogger(RegisterUserServlet.class);
    private static final Gson GSON = new Gson();
    
    @Reference
    private ResourceResolverFactory resolverFactory;

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) 
            throws IOException {
        
        LOG.info("👤 User registration request received");
        
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
            String type = requestData.has("type") ? requestData.get("type").getAsString() : "unknown";
            
            LOG.info("  📍 Address: {}", address);
            LOG.info("  🔐 Type: {}", type);
            
            // TODO: Verify signature (for MetaMask registrations)
            if ("metamask".equals(type) && requestData.has("signature")) {
                String signature = requestData.get("signature").getAsString();
                String message = requestData.get("message").getAsString();
                
                LOG.info("  ✍️  Signature: {}...", signature.substring(0, 20));
                LOG.warn("  ⚠️  DEMO MODE: Signature verification skipped");
                LOG.warn("     In production, verify: ECRecover.ecrecover(message, signature) == address");
            }
            
            // Get service resource resolver for user creation
            // Anonymous users can't create users, so we use a service user with specific permissions
            Map<String, Object> authInfo = new HashMap<>();
            authInfo.put(ResourceResolverFactory.SUBSERVICE, "blockchain-aem-registration");
            
            ResourceResolver serviceResolver = null;
            try {
                // Try service user first (production pattern)
                try {
                    serviceResolver = resolverFactory.getServiceResourceResolver(authInfo);
                    LOG.info("  🔐 Using service user: blockchain-aem-registration");
                } catch (LoginException e) {
                    // Fallback for demo: use admin credentials
                    LOG.warn("  ⚠️  Service user not available, using admin fallback for demo");
                    LOG.warn("     Production deployment should configure service user mapping");
                    Map<String, Object> adminAuth = new HashMap<>();
                    adminAuth.put(ResourceResolverFactory.USER, "admin");
                    adminAuth.put(ResourceResolverFactory.PASSWORD, "admin".toCharArray());
                    serviceResolver = resolverFactory.getResourceResolver(adminAuth);
                }
                
                // Get JCR session from resource resolver
                Session session = serviceResolver.adaptTo(Session.class);
                if (session == null) {
                    throw new IllegalStateException("JCR Session not available");
                }
                
                // Get UserManager from JCR session
                UserManager userManager = ((JackrabbitSession) session).getUserManager();
                if (userManager == null) {
                    throw new IllegalStateException("UserManager not available");
                }
            
            // Check if user already exists
            Authorizable existing = userManager.getAuthorizable(address);
            
            if (existing != null) {
                LOG.info("  ℹ️  User already exists: {}", address);
                
                JsonObject responseData = new JsonObject();
                responseData.addProperty("success", true);
                responseData.addProperty("address", address);
                responseData.addProperty("message", "User already registered");
                responseData.addProperty("existing", true);
                
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(GSON.toJson(responseData));
                return;
            }
            
            // Create new user
            LOG.info("  🆕 Creating new user: {}", address);
            
            // Derive deterministic password from wallet address
            // This allows consistent authentication via Web3AuthenticationHandler
            String derivedPassword = PasswordDerivation.derivePassword(address);
            LOG.info("  🔐 Derived password for wallet-based auth");
            
            // Create principal
            Principal principal = new Principal() {
                @Override
                public String getName() {
                    return address;
                }
            };
            
            // Create user with derived password
            User user = userManager.createUser(
                address,           // User ID (wallet address)
                derivedPassword,   // Deterministic password from wallet
                principal,         // Principal
                null               // Use default path (sharded)
            );
            
            LOG.info("  ✅ User created: {}", address);
            
            // Add to administrators group (if it exists)
            boolean hasAdminAccess = false;
            Group adminGroup = (Group) userManager.getAuthorizable("administrators");
            if (adminGroup != null) {
                adminGroup.addMember(user);
                LOG.info("  ✅ Added to administrators group");
                hasAdminAccess = true;
            } else {
                // Sling doesn't have groups by default - grant direct ACL permissions
                LOG.info("  ℹ️  No administrators group (Sling mode) - granting direct permissions");
                hasAdminAccess = grantAdminPermissions(session, user);
            }
            
                // Save changes
                serviceResolver.commit();
                
                LOG.info("  💾 Changes committed to repository");
                LOG.info("✅ User registration successful: {}", address);
                LOG.info("   User can now authenticate with wallet");
                
                JsonObject responseData = new JsonObject();
                responseData.addProperty("success", true);
                responseData.addProperty("address", address);
                responseData.addProperty("message", "Account created successfully");
                responseData.addProperty("userId", address);
                responseData.addProperty("path", user.getPath());
                responseData.addProperty("isAdmin", hasAdminAccess);
                
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(GSON.toJson(responseData));
                
            } finally {
                if (serviceResolver != null && serviceResolver.isLive()) {
                    serviceResolver.close();
                }
            }
            
        } catch (Exception e) {
            LOG.error("❌ User registration failed", e);
            
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
    
    /**
     * Grants admin-like permissions directly via ACLs.
     * Used in Sling (non-AEM) environments where groups don't exist.
     * 
     * <p>For demo purposes, grants jcr:all on key content paths.
     * Production deployments should use proper group-based permissions.
     */
    private boolean grantAdminPermissions(Session session, User user) {
        try {
            AccessControlManager acm = session.getAccessControlManager();
            Principal principal = user.getPrincipal();
            
            // Paths to grant permissions on for demo
            String[] contentPaths = {
                "/content",
                "/content/blockchain-aem",
                "/apps",
                "/oak-chain"
            };
            
            // Get jcr:all privilege (full access)
            Privilege[] privileges = new Privilege[] {
                acm.privilegeFromName(Privilege.JCR_ALL)
            };
            
            int granted = 0;
            for (String path : contentPaths) {
                try {
                    // Check if path exists
                    if (!session.nodeExists(path)) {
                        LOG.debug("  ⏭️  Path doesn't exist, skipping: {}", path);
                        continue;
                    }
                    
                    // Get or create ACL for this path
                    JackrabbitAccessControlList acl = null;
                    
                    // First check existing policies
                    for (AccessControlPolicy policy : acm.getPolicies(path)) {
                        if (policy instanceof JackrabbitAccessControlList) {
                            acl = (JackrabbitAccessControlList) policy;
                            break;
                        }
                    }
                    
                    // If no ACL exists, get applicable policies
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
                        // Add ACE for the user
                        acl.addAccessControlEntry(principal, privileges);
                        acm.setPolicy(path, acl);
                        LOG.info("  ✅ Granted jcr:all on {}", path);
                        granted++;
                    } else {
                        LOG.warn("  ⚠️  Could not get ACL for: {}", path);
                    }
                    
                } catch (Exception e) {
                    LOG.warn("  ⚠️  Failed to set ACL on {}: {}", path, e.getMessage());
                }
            }
            
            if (granted > 0) {
                LOG.info("  ✅ Granted permissions on {} paths", granted);
                return true;
            } else {
                LOG.warn("  ⚠️  No permissions granted (paths may not exist yet)");
                return false;
            }
            
        } catch (Exception e) {
            LOG.error("  ❌ Failed to grant admin permissions", e);
            return false;
        }
    }
}

