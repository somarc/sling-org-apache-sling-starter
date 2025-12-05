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
package com.adobe.aem.blockchain.auth;

import com.adobe.aem.blockchain.utils.PasswordDerivation;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Custom Sling AuthenticationHandler for Web3 authentication (MetaMask + Biometrics).
 * 
 * This handler:
 * - Recognizes the "blockchain.aem.auth" cookie
 * - Extracts wallet address from cookie
 * - Provides authentication info to ResourceResolverFactory
 * - Integrates with Oak JAAS (Web3BiometricLoginModule)
 */
@Component(
    service = AuthenticationHandler.class,
    property = {
        // Protected content paths
        AuthenticationHandler.PATH_PROPERTY + "=/content/blockchain-aem",
        
        // Protected API endpoints (blockchain operations after login)
        AuthenticationHandler.PATH_PROPERTY + "=/bin/blockchain",
        AuthenticationHandler.PATH_PROPERTY + "=/api/blockchain",
        
        // Protected tools
        AuthenticationHandler.PATH_PROPERTY + "=/bin/browser.html",
        AuthenticationHandler.PATH_PROPERTY + "=/blockchain-aem/chat",
        AuthenticationHandler.PATH_PROPERTY + "=/v1/chat",
        
        // NOTE: /bin/blockchain-aem/* login endpoints handled separately via sling.auth.requirements
        // Login endpoints (/bin/blockchain-aem/biometric-login, /bin/blockchain-aem/metamask-login, etc.) 
        // are PUBLIC and don't require this handler
        
        AuthenticationHandler.TYPE_PROPERTY + "=Web3 Authentication Handler",
        "service.ranking:Integer=50"  // Lower than form auth, so admin login still works
    }
)
public class Web3AuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {
    
    private static final Logger LOG = LoggerFactory.getLogger(Web3AuthenticationHandler.class);
    private static final String AUTH_COOKIE_NAME = "blockchain.aem.auth";
    private static final String AUTH_TYPE = "WEB3";
    
    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        LOG.debug("🔐 Web3AuthenticationHandler.extractCredentials() called for: {}", request.getRequestURI());
        
        // Look for our authentication cookie
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            LOG.debug("   No cookies found");
            return null;
        }
        
        String walletAddress = null;
        for (Cookie cookie : cookies) {
            if (AUTH_COOKIE_NAME.equals(cookie.getName())) {
                walletAddress = cookie.getValue();
                LOG.debug("   Found Web3 auth cookie for wallet: {}", walletAddress);
                break;
            }
        }
        
        if (walletAddress == null) {
            LOG.debug("   No Web3 auth cookie found");
            return null;
        }
        
        // Create AuthenticationInfo with credentials for Oak JAAS
        // ResourceResolverFactory will use these to authenticate via repository.login()
        try {
            String derivedPassword = PasswordDerivation.derivePassword(walletAddress);
            
            AuthenticationInfo info = new AuthenticationInfo(AUTH_TYPE, walletAddress);
            
            // Set both the user ID and password that Sling's JCR ResourceProvider expects
            info.put(ResourceResolverFactory.USER, walletAddress);
            info.put(ResourceResolverFactory.PASSWORD, derivedPassword.toCharArray());
            
            // Create JCR credentials with Web3 attributes for Oak LoginModule
            javax.jcr.SimpleCredentials jcrCreds = new javax.jcr.SimpleCredentials(
                walletAddress,
                derivedPassword.toCharArray()
            );
            
            // CRITICAL: Set attributes that Web3BiometricLoginModule expects
            jcrCreds.setAttribute("web3.metamask.verified", Boolean.TRUE);
            jcrCreds.setAttribute("web3.metamask.address", walletAddress);
            
            // Provide JCR credentials to Sling
            info.put("user.jcr.credentials", jcrCreds);
            
            LOG.info("✅ Web3 authentication extracted for wallet: {}", walletAddress);
            LOG.debug("   Provided USER={}, PASSWORD=(derived), JCR credentials with Web3 attributes", walletAddress);
            return info;
            
        } catch (Exception e) {
            LOG.error("Failed to create authentication info", e);
            return null;
        }
    }
    
    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.debug("🔐 Web3AuthenticationHandler.requestCredentials() called");
        
        // Redirect to login page
        String loginUrl = "/starter.html";
        String resource = request.getParameter("resource");
        if (resource != null && !resource.isEmpty()) {
            loginUrl += "?resource=" + resource;
        }
        
        LOG.info("   Redirecting to login: {}", loginUrl);
        response.sendRedirect(loginUrl);
        return true;
    }
    
    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("🔐 Web3AuthenticationHandler.dropCredentials() - logging out");
        
        // Clear the authentication cookie
        Cookie cookie = new Cookie(AUTH_COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        
        LOG.info("   Web3 auth cookie cleared");
    }
}

