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
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import java.io.IOException;

/**
 * Servlet that handles content publishing to Oak Chain after MetaMask payment.
 * 
 * <p>This servlet receives content submission requests after users have paid
 * validators via the ValidatorPaymentV3_1 smart contract. It then writes the
 * content to the Oak validators which will replicate it via Aeron consensus.</p>
 * 
 * <p><strong>Flow:</strong></p>
 * <ol>
 *   <li>User pays with MetaMask → ValidatorPaymentV3_1.payForProposal()</li>
 *   <li>Smart contract emits ProposalPaid event</li>
 *   <li>Frontend calls this servlet with content + proposalId + txHash</li>
 *   <li>Servlet writes to Oak validators via wallet-signed proposal</li>
 *   <li>Validators listen for blockchain events and process content</li>
 * </ol>
 * 
 * <p><strong>POC Note:</strong> This is a mock implementation. In production, this would:</p>
 * <ul>
 *   <li>Verify the blockchain transaction via Web3 provider</li>
 *   <li>Submit a signed write proposal to validators</li>
 *   <li>Wait for Aeron consensus confirmation</li>
 *   <li>Return the replicated content path</li>
 * </ul>
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain/oak-chain-publish",
        "sling.servlet.methods=POST"
    }
)
public class OakChainPublishServlet extends SlingAllMethodsServlet {

    private static final Logger log = LoggerFactory.getLogger(OakChainPublishServlet.class);

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Get parameters
        String path = request.getParameter("path");
        String title = request.getParameter("title");
        String content = request.getParameter("content");
        String proposalId = request.getParameter("proposalId");
        String txHash = request.getParameter("txHash");
        String tier = request.getParameter("tier");
        
        // Three-address model
        String contentOwner = request.getParameter("contentOwner");  // Sling Author address
        String paidBy = request.getParameter("paidBy");              // MetaMask user address
        String wallet = request.getParameter("wallet");              // Legacy field

        log.info("Oak Chain publish request received:");
        log.info("  Path: {}", path);
        log.info("  Title: {}", title);
        log.info("  Proposal ID: {}", proposalId);
        log.info("  Tx Hash: {}", txHash);
        log.info("  Tier: {}", tier);
        log.info("  Content Owner (Sling Author): {}", contentOwner);
        log.info("  Paid By (MetaMask User): {}", paidBy);
        log.info("  Wallet (Legacy): {}", wallet);

        // Validate required parameters
        if (path == null || title == null || content == null || proposalId == null || txHash == null) {
            response.setStatus(400);
            response.getWriter().write("{\"success\":false,\"error\":\"Missing required parameters\"}");
            return;
        }

        try {
            // POC: Mock successful submission
            // In production, this would:
            // 1. Create a signed write proposal using the Sling Author's wallet signature
            // 2. Submit to validator's /v1/proposals endpoint
            // 3. Validators verify blockchain payment event (checking paidBy address)
            // 4. Aeron consensus replicates content across all validators
            // 5. Content appears at /oak-chain/content/{contentOwner}/{path}

            // Three-address model: Content stored under Sling Author's address
            String shardedPath = String.format("/oak-chain/content/%s%s", 
                contentOwner != null ? contentOwner : "default",
                path.startsWith("/") ? path : "/" + path
            );

            log.info("✅ Mock: Content would be written to {} after validator processing", shardedPath);
            log.info("   Three-address model:");
            log.info("     - Content Owner (storage): {}", contentOwner);
            log.info("     - Paid By (transaction): {}", paidBy);
            log.info("     - Validators: Will receive payment from smart contract");
            log.info("   Validators will listen for ProposalPaid event (txHash: {})", txHash);
            log.info("   Content will be replicated via Aeron consensus");

            // Return success response with three-address info
            String json = String.format(
                "{\n" +
                "  \"success\": true,\n" +
                "  \"message\": \"Content queued for Oak Chain publishing\",\n" +
                "  \"proposalId\": \"%s\",\n" +
                "  \"txHash\": \"%s\",\n" +
                "  \"expectedPath\": \"%s\",\n" +
                "  \"tier\": \"%s\",\n" +
                "  \"contentOwner\": \"%s\",\n" +
                "  \"paidBy\": \"%s\",\n" +
                "  \"status\": \"PENDING_CONSENSUS\",\n" +
                "  \"architecture\": \"Three-address model: Content owned by Sling Author, paid by MetaMask user\",\n" +
                "  \"note\": \"POC: In production, validators would verify blockchain event and replicate content\"\n" +
                "}",
                proposalId,
                txHash,
                shardedPath,
                tier,
                contentOwner != null ? contentOwner : "null",
                paidBy != null ? paidBy : "null"
            );

            response.getWriter().write(json);

        } catch (Exception e) {
            log.error("Error processing Oak Chain publish request", e);
            response.setStatus(500);
            response.getWriter().write(
                String.format(
                    "{\"success\":false,\"error\":\"Server error: %s\"}",
                    e.getMessage()
                )
            );
        }
    }
}

