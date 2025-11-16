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

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OSGi servlet that provides LLM chat interface for Sling authors.
 * 
 * <p>Wraps the oak-segment-agentic ChatHandler to provide AI-powered assistance
 * for troubleshooting Sling state, Oak internals, and validator connectivity.</p>
 * 
 * <p>Requires oak-segment-agentic bundle to be installed.</p>
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/v1/chat",
        "sling.servlet.methods=POST"
    },
    immediate = true
)
public class ChatServlet extends SlingAllMethodsServlet {
    private static final Logger log = LoggerFactory.getLogger(ChatServlet.class);
    
    private volatile Object chatHandler; // ChatHandler from oak-segment-agentic (optional)
    private BundleContext bundleContext;
    
    @Activate
    protected void activate(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
        log.info("ChatServlet activated with BundleContext");
    }
    
    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        
        // Check authentication - ensure user is admin
        if (!isAuthenticated(request)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"error\":\"Admin access required. Only admin users can access the chat service.\"}");
            return;
        }
        
        // Lazy initialization of chat handler
        if (chatHandler == null) {
            synchronized (this) {
                if (chatHandler == null) {
                    // Try to get base URL from request
                    String baseUrl = buildBaseUrl(request);
                    chatHandler = initializeChatHandler(baseUrl);
                }
            }
        }
        
        if (chatHandler == null) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"error\":\"Chat service not available. Ensure oak-segment-agentic bundle is installed.\"}");
            return;
        }
        
        try {
            // Use reflection to call handleChat method (to avoid hard dependency)
            java.lang.reflect.Method handleMethod = chatHandler.getClass()
                .getMethod("handleChat", HttpServletRequest.class, HttpServletResponse.class);
            handleMethod.invoke(chatHandler, request, response);
        } catch (Exception e) {
            log.error("Error invoking chat handler", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"error\":\"Chat handler error: " + e.getMessage() + "\"}");
        }
    }
    
    /**
     * Build base URL from request.
     */
    private String buildBaseUrl(SlingHttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        
        StringBuilder url = new StringBuilder();
        url.append(scheme).append("://").append(serverName);
        if ((scheme.equals("http") && serverPort != 80) || 
            (scheme.equals("https") && serverPort != 443)) {
            url.append(":").append(serverPort);
        }
        return url.toString();
    }
    
    /**
     * Initialize chat handler using reflection (optional dependency).
     * Uses BundleContext to load classes from the oak-segment-agentic bundle.
     */
    private Object initializeChatHandler(String baseUrl) {
        if (bundleContext == null) {
            log.warn("BundleContext not available - cannot load chat handler");
            return null;
        }
        
        try {
            // Use provided baseUrl or fallback to system property/default
            if (baseUrl == null || baseUrl.isEmpty()) {
                baseUrl = System.getProperty("sling.server.url");
                if (baseUrl == null || baseUrl.isEmpty()) {
                    baseUrl = "http://localhost:8080";
                }
            }
            
            // Find the oak-segment-agentic bundle
            Bundle agenticBundle = null;
            for (Bundle bundle : bundleContext.getBundles()) {
                if ("org.apache.jackrabbit.oak-segment-agentic".equals(bundle.getSymbolicName())) {
                    agenticBundle = bundle;
                    break;
                }
            }
            
            if (agenticBundle == null) {
                log.debug("oak-segment-agentic bundle not found");
                return null;
            }
            
            if (agenticBundle.getState() != Bundle.ACTIVE) {
                log.debug("oak-segment-agentic bundle is not active (state: {})", agenticBundle.getState());
                return null;
            }
            
            // Load classes from the agentic bundle using its BundleContext
            // Load interface for constructor signature
            Class<?> llmServiceInterface = agenticBundle.loadClass("org.apache.jackrabbit.oak.segment.agentic.llm.LLMService");
            // Load concrete implementation to instantiate
            Class<?> ollamaLLMServiceClass = agenticBundle.loadClass("org.apache.jackrabbit.oak.segment.agentic.llm.OllamaLLMService");
            Class<?> ragServiceClass = agenticBundle.loadClass("org.apache.jackrabbit.oak.segment.agentic.rag.RAGService");
            Class<?> chatHandlerClass = agenticBundle.loadClass("org.apache.jackrabbit.oak.segment.agentic.chat.ChatHandler");
            
            // Create instances
            Object llmService = ollamaLLMServiceClass.getConstructor().newInstance();
            Object ragService = ragServiceClass.getConstructor().newInstance();
            // Constructor expects LLMService interface, but accepts OllamaLLMService instance (implements LLMService)
            Object handler = chatHandlerClass.getConstructor(
                llmServiceInterface,
                ragServiceClass,
                String.class
            ).newInstance(llmService, ragService, baseUrl);
            
            log.info("✅ LLM Chat handler initialized (oak-segment-agentic module available) with baseUrl: {}", baseUrl);
            return handler;
        } catch (ClassNotFoundException e) {
            log.debug("oak-segment-agentic module not available - chat endpoint disabled: {}", e.getMessage());
            return null;
        } catch (NoSuchMethodException e) {
            log.warn("Constructor not found for chat handler classes: {}", e.getMessage(), e);
            return null;
        } catch (Exception e) {
            log.warn("Failed to initialize chat handler: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Check if the request is authenticated and user is admin.
     * Chat service requires admin privileges for security.
     */
    private boolean isAuthenticated(SlingHttpServletRequest request) {
        try {
            String userId = request.getResourceResolver().getUserID();
            // Check if user is authenticated and is admin
            // In Sling/Oak, admin user ID is typically "admin"
            return userId != null && 
                   !userId.equals("anonymous") && 
                   !userId.isEmpty() &&
                   userId.equals("admin"); // Only admin user can access chat
        } catch (Exception e) {
            log.debug("Error checking authentication", e);
            return false;
        }
    }
}

