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

import com.google.gson.JsonObject;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Custom session info servlet that works with Web3 authentication.
 * 
 * <p>Provides session information including the authenticated user's wallet address.
 * This endpoint is under /bin/blockchain/ so the Web3AuthenticationHandler can
 * process the authentication cookie.</p>
 * 
 * <p>Replaces /system/sling/info.sessionInfo.json for Web3-authenticated sessions.</p>
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain/session-info",
        "sling.servlet.methods=GET"
    }
)
public class SessionInfoServlet extends SlingAllMethodsServlet {

    private static final Logger LOG = LoggerFactory.getLogger(SessionInfoServlet.class);

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            // Get the authenticated user from the resource resolver
            String userId = request.getResourceResolver().getUserID();
            
            LOG.debug("Session info requested - User ID: {}", userId);
            
            // Build JSON response compatible with Sling's sessionInfo format
            JsonObject sessionInfo = new JsonObject();
            sessionInfo.addProperty("userID", userId != null ? userId : "anonymous");
            
            // Additional info for debugging
            sessionInfo.addProperty("authenticated", userId != null && !"anonymous".equals(userId));
            if (userId != null && userId.startsWith("0x")) {
                sessionInfo.addProperty("walletAddress", userId);
                sessionInfo.addProperty("authType", "web3");
            }
            
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write(sessionInfo.toString());
            
        } catch (Exception e) {
            LOG.error("Error getting session info", e);
            
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("userID", "anonymous");
            errorResponse.addProperty("error", e.getMessage());
            
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write(errorResponse.toString());
        }
    }
}

