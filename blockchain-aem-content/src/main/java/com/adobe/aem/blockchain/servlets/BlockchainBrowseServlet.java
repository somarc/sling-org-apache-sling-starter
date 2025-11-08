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

import javax.servlet.Servlet;
import java.io.IOException;

/**
 * Servlet that provides access to blockchain genesis content via HTTP Segment Transfer.
 * 
 * <p>This is a POC implementation that returns mock data demonstrating the connection
 * to a GlobalStoreServer and retrieval of genesis content from the blockchain.</p>
 * 
 * <p>In a production implementation, this would connect to an actual HTTP Segment Transfer
 * endpoint and retrieve real genesis content from the distributed blockchain store.</p>
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain/browse",
        "sling.servlet.methods=GET"
    }
)
public class BlockchainBrowseServlet extends SlingAllMethodsServlet {

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        // Mock JSON response matching the expected structure
        String json = "{\n" +
            "  \"status\": \"CONNECTED\",\n" +
            "  \"message\": \"Successfully connected to GlobalStoreServer\",\n" +
            "  \"globalStore\": {\n" +
            "    \"url\": \"http://localhost:8090\",\n" +
            "    \"protocol\": \"HTTP Segment Transfer\"\n" +
            "  },\n" +
            "  \"genesis\": {\n" +
            "    \"path\": \"/oak-chain/content/genesis\",\n" +
            "    \"message\": \"DO IT LIVE!\",\n" +
            "    \"description\": \"Genesis block for Blockchain AEM POC - establishing immutable content foundation\",\n" +
            "    \"author\": \"Blockchain AEM Team\",\n" +
            "    \"version\": \"1.0.0-SNAPSHOT\",\n" +
            "    \"note\": \"Stored in Oak SegmentNodeStore with HTTP Segment Transfer capability\"\n" +
            "  },\n" +
            "  \"capabilities\": {\n" +
            "    \"httpSegmentTransfer\": true,\n" +
            "    \"genesisContent\": true,\n" +
            "    \"byodModel\": true,\n" +
            "    \"consensusProtocol\": \"Proof of Authority (POC)\"\n" +
            "  }\n" +
            "}";
        
        response.getWriter().write(json);
    }
}

