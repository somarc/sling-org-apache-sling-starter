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

import com.adobe.aem.blockchain.config.BlockchainConfigService;
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
 * Servlet that exposes Blockchain AEM configuration to the frontend.
 * 
 * This provides the client's blockchain mode without CORS issues.
 * Each Sling client knows its own mode independently.
 */
@Component(
    service = Servlet.class,
    property = {
        "sling.servlet.paths=/bin/blockchain/config",
        "sling.servlet.methods=GET"
    }
)
public class BlockchainConfigServlet extends SlingAllMethodsServlet {

    private static final Logger log = LoggerFactory.getLogger(BlockchainConfigServlet.class);

    @Reference
    private BlockchainConfigService configService;

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws IOException {
        
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        // Add CORS headers for good measure (though not needed for same-origin)
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET");

        String json = String.format(
            "{" +
            "\"mode\":\"%s\"," +
            "\"displayName\":\"%s\"," +
            "\"badgeColor\":\"%s\"," +
            "\"validatorUrl\":\"%s\"," +
            "\"requiresMetaMask\":%s," +
            "\"contractAddress\":\"%s\"" +
            "}",
            configService.getMode(),
            configService.getModeDisplayName(),
            configService.getBadgeColor(),
            configService.getValidatorUrl(),
            configService.isRequiresMetaMask(),
            configService.getContractAddress()
        );

        log.debug("Blockchain config requested: mode={}", configService.getMode());
        response.getWriter().write(json);
    }
}

