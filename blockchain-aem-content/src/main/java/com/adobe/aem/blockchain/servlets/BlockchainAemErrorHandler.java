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
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;

/**
 * Error handler for blockchain-aem pages.
 * 
 * When a 404 or 401 occurs on /content/blockchain-aem/*, 
 * redirect to /starter.html instead of showing ugly error pages.
 * 
 * This provides a better UX during:
 * - Sling startup (content not yet deployed)
 * - Session expiry
 * - Typos in URLs
 */
@Component(
    service = Servlet.class,
    property = {
        // Handle 404 errors for blockchain-aem paths
        "sling.servlet.resourceTypes=sling/servlet/errorhandler",
        "sling.servlet.selectors=404",
        "sling.servlet.extensions=html",
        "sling.servlet.methods=GET",
        "service.ranking:Integer=100"
    }
)
public class BlockchainAemErrorHandler extends SlingSafeMethodsServlet {
    
    private static final Logger LOG = LoggerFactory.getLogger(BlockchainAemErrorHandler.class);
    
    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response) 
            throws ServletException, IOException {
        
        String requestUri = request.getRequestURI();
        
        // Only redirect for blockchain-aem pages
        if (requestUri != null && requestUri.startsWith("/content/blockchain-aem")) {
            LOG.info("🔄 404 on blockchain-aem page: {} → redirecting to /starter.html", requestUri);
            response.sendRedirect("/starter.html?resource=" + requestUri);
            return;
        }
        
        // For other 404s, show default error page
        response.setStatus(404);
        response.setContentType("text/html");
        response.getWriter().write(
            "<!DOCTYPE html><html><head><title>404 Not Found</title></head>" +
            "<body><h1>404 - Page Not Found</h1><p>The requested resource was not found.</p>" +
            "<p><a href='/starter.html'>Go to Blockchain AEM</a></p></body></html>"
        );
    }
}

