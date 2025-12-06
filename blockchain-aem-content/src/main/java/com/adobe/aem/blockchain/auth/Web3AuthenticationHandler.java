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
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Custom Sling AuthenticationHandler for Web3 authentication (MetaMask + Biometrics).
 * 
 * This handler:
 * - Recognizes the "blockchain.aem.auth" cookie
 * - Extracts wallet address from cookie
 * - Provides authentication info to ResourceResolverFactory
 * - Integrates with Oak JAAS (Web3BiometricLoginModule)
 * - Sets AUTH_INFO_LOGIN on first login to trigger Sling's session persistence
 * 
 * Flow:
 * 1. Login servlet authenticates via Oak JAAS, sets auth cookie + "login marker" cookie
 * 2. extractCredentials() detects login marker, returns AuthInfo with AUTH_INFO_LOGIN
 * 3. Sling creates ResourceResolver, fires LOGIN event, establishes HTTP session
 * 4. Subsequent requests: extractCredentials() returns AuthInfo without AUTH_INFO_LOGIN
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
        
        AuthenticationHandler.TYPE_PROPERTY + "=WEB3",
        "service.ranking:Integer=100"  // Higher ranking to take precedence
    }
)
public class Web3AuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {
    
    private static final Logger LOG = LoggerFactory.getLogger(Web3AuthenticationHandler.class);
    
    /** Main authentication cookie - contains wallet address */
    private static final String AUTH_COOKIE_NAME = "blockchain.aem.auth";
    
    /** Login marker cookie - indicates fresh login, triggers AUTH_INFO_LOGIN */
    private static final String LOGIN_MARKER_COOKIE = "blockchain.aem.login";
    
    /** Session attribute to track authenticated wallet */
    private static final String SESSION_ATTR_WALLET = "blockchain.aem.wallet";
    
    private static final String AUTH_TYPE = "WEB3";
    
    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        LOG.debug("🔐 Web3AuthenticationHandler.extractCredentials() for: {}", request.getRequestURI());
        
        // Look for our authentication cookie
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            LOG.debug("   No cookies found");
            return null;
        }
        
        String walletAddress = null;
        boolean isLoginMarker = false;
        
        for (Cookie cookie : cookies) {
            if (AUTH_COOKIE_NAME.equals(cookie.getName())) {
                walletAddress = cookie.getValue();
            } else if (LOGIN_MARKER_COOKIE.equals(cookie.getName())) {
                isLoginMarker = "true".equals(cookie.getValue());
            }
        }
        
        if (walletAddress == null || walletAddress.isEmpty()) {
            LOG.debug("   No Web3 auth cookie found");
            return null;
        }
        
        LOG.debug("   Found Web3 auth cookie for wallet: {}", walletAddress);
        
        // Check if this is a fresh login (login marker set and session doesn't have our attribute)
        HttpSession session = request.getSession(false);
        boolean isFreshLogin = isLoginMarker || 
            (session == null) || 
            (!walletAddress.equals(session.getAttribute(SESSION_ATTR_WALLET)));
        
        // Create AuthenticationInfo with credentials for Oak JAAS
        try {
            String derivedPassword = PasswordDerivation.derivePassword(walletAddress);
            
            AuthenticationInfo info = new AuthenticationInfo(AUTH_TYPE, walletAddress);
            
            // Set credentials for ResourceResolverFactory
            info.put(ResourceResolverFactory.USER, walletAddress);
            info.put(ResourceResolverFactory.PASSWORD, derivedPassword.toCharArray());
            
            // Create JCR credentials with Web3 attributes for Oak LoginModule
            javax.jcr.SimpleCredentials jcrCreds = new javax.jcr.SimpleCredentials(
                walletAddress,
                derivedPassword.toCharArray()
            );
            jcrCreds.setAttribute("web3.metamask.verified", Boolean.TRUE);
            jcrCreds.setAttribute("web3.metamask.address", walletAddress);
            info.put("user.jcr.credentials", jcrCreds);
            
            // CRITICAL: If this is a fresh login, set AUTH_INFO_LOGIN
            // This tells Sling to fire the LOGIN event and establish proper session
            if (isFreshLogin) {
                LOG.info("🎉 Fresh Web3 login detected for wallet: {}", walletAddress);
                info.put(AuthConstants.AUTH_INFO_LOGIN, Boolean.TRUE);
                
                // Clear the login marker cookie (one-time use)
                if (isLoginMarker) {
                    Cookie clearMarker = new Cookie(LOGIN_MARKER_COOKIE, "");
                    clearMarker.setPath("/");
                    clearMarker.setMaxAge(0);
                    response.addCookie(clearMarker);
                }
                
                // Store wallet in session on successful authentication
                // (will be set after ResourceResolver is created)
            } else {
                LOG.debug("   Existing session for wallet: {}", walletAddress);
            }
            
            LOG.info("✅ Web3 credentials extracted: user={}, freshLogin={}", walletAddress, isFreshLogin);
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
            loginUrl += "?resource=" + java.net.URLEncoder.encode(resource, "UTF-8");
        }
        
        LOG.info("   Redirecting to login: {}", loginUrl);
        response.sendRedirect(loginUrl);
        return true;
    }
    
    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("🔐 Web3AuthenticationHandler.dropCredentials() - logging out");
        
        // Clear the authentication cookie
        Cookie authCookie = new Cookie(AUTH_COOKIE_NAME, "");
        authCookie.setPath("/");
        authCookie.setMaxAge(0);
        response.addCookie(authCookie);
        
        // Clear the login marker cookie
        Cookie markerCookie = new Cookie(LOGIN_MARKER_COOKIE, "");
        markerCookie.setPath("/");
        markerCookie.setMaxAge(0);
        response.addCookie(markerCookie);
        
        // Invalidate HTTP session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(SESSION_ATTR_WALLET);
            session.invalidate();
        }
        
        LOG.info("   Web3 authentication cleared: cookies + session");
    }
    
    /**
     * Called after successful authentication.
     * Store the wallet in session to track authenticated state.
     * 
     * @return true if request processing should stop (redirect sent), false to continue
     */
    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, 
                                           AuthenticationInfo authInfo) {
        String wallet = authInfo.getUser();
        if (wallet != null) {
            HttpSession session = request.getSession(true);
            session.setAttribute(SESSION_ATTR_WALLET, wallet);
            LOG.info("✅ Web3 auth succeeded, wallet stored in session: {}", wallet);
        }
        
        // Call parent to handle any redirect
        return super.authenticationSucceeded(request, response, authInfo);
    }
}

