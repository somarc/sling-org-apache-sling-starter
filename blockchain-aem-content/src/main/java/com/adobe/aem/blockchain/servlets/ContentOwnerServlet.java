/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.adobe.aem.blockchain.servlets;

import org.apache.jackrabbit.oak.segment.http.wallet.SlingAuthorWalletService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import java.io.IOException;

/**
 * Servlet that returns the Sling Author's Ethereum wallet address.
 * 
 * This is used by the frontend to:
 * - Display the content owner address
 * - Calculate the storage path for content
 * - Show where content will be stored in the oak-chain mount
 * 
 * Three-Address Architecture:
 * - Content Owner (Sling Author): This wallet - owns the content
 * - Payer (MetaMask User): Pays for transaction
 * - Validators: Receive payment and replicate content
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain/content-owner",
        "sling.servlet.methods=GET"
    }
)
public class ContentOwnerServlet extends SlingAllMethodsServlet {

    private static final Logger log = LoggerFactory.getLogger(ContentOwnerServlet.class);

    @Reference
    private SlingAuthorWalletService walletService;

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        if (walletService == null || !walletService.isAvailable()) {
            log.warn("Sling Author wallet service not available");
            response.setStatus(503);
            response.getWriter().write(
                "{\"error\":\"Wallet service not available\",\"address\":null}"
            );
            return;
        }

        String walletAddress = walletService.getWalletAddress();
        
        if (walletAddress == null) {
            log.warn("Sling Author wallet address is null");
            response.setStatus(503);
            response.getWriter().write(
                "{\"error\":\"Wallet not initialized\",\"address\":null}"
            );
            return;
        }

        log.debug("Content owner address requested: {}", walletAddress);

        // Return JSON with wallet address
        String json = String.format(
            "{\"address\":\"%s\",\"shard\":\"%s\"}",
            walletAddress,
            walletAddress.substring(2, 4)  // First 2 hex chars for sharding
        );

        response.getWriter().write(json);
    }
}

