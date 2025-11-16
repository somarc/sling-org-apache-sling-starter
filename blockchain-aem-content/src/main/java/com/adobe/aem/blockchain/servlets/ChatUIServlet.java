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
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

/**
 * Servlet that serves the Agentic Chat UI HTML page.
 * 
 * <p>Provides a web interface for interacting with the oak-segment-agentic
 * chat functionality. The UI allows users to ask questions about Oak internals,
 * Sling state, validator connectivity, and log analysis.</p>
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/blockchain-aem/chat",
        "sling.servlet.methods=GET"
    },
    immediate = true
)
public class ChatUIServlet extends SlingSafeMethodsServlet {
    private static final Logger log = LoggerFactory.getLogger(ChatUIServlet.class);
    
    @Activate
    protected void activate() {
        log.info("ChatUIServlet activated - serving agentic-chat.html");
    }

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        
        log.debug("ChatUIServlet.doGet called for path: {}", request.getPathInfo());
        
        // Check authentication - ensure user is admin
        if (!isAuthenticated(request)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(
                "<html><head><title>Admin Access Required</title></head><body>" +
                "<h1>Admin Access Required</h1>" +
                "<p>Only admin users can access the chat interface.</p>" +
                "<p>Please <a href=\"/system/sling/login\">log in as admin</a> to access this service.</p>" +
                "</body></html>"
            );
            return;
        }
        
        response.setContentType("text/html;charset=UTF-8");
        
        // Load the HTML file from resources
        // Try multiple possible paths
        InputStream htmlStream = getClass().getClassLoader()
            .getResourceAsStream("SLING-INF/content/content/blockchain-aem/agentic-chat.html");
        
        if (htmlStream == null) {
            // Fallback: try without SLING-INF prefix
            htmlStream = getClass().getResourceAsStream("/SLING-INF/content/content/blockchain-aem/agentic-chat.html");
        }
        
        if (htmlStream == null) {
            // Last resort: try relative to this class
            htmlStream = getClass().getResourceAsStream("agentic-chat.html");
        }
        
        if (htmlStream == null) {
            log.error("agentic-chat.html not found in bundle resources. Tried paths:");
            log.error("  - SLING-INF/content/content/blockchain-aem/agentic-chat.html");
            log.error("  - /SLING-INF/content/content/blockchain-aem/agentic-chat.html");
            log.error("  - agentic-chat.html");
            response.setStatus(404);
            response.getWriter().write("<h1>Chat UI not found</h1><p>Please ensure the HTML file is in the bundle resources.</p>");
            return;
        }
        
        log.debug("Found agentic-chat.html, streaming to response");
        
        // Stream the HTML content
        try {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = htmlStream.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        } finally {
            htmlStream.close();
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

