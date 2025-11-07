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
package org.apache.sling.starter.blockchain;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.osgi.service.component.annotations.Component;

/**
 * Blockchain AEM Browser Servlet
 *
 * Connects to GlobalStoreServer via HTTP and displays the genesis content
 * and global chain information.
 */
@Component(
        service = Servlet.class,
        property = {"sling.servlet.paths=/bin/blockchain/browse", "sling.servlet.methods=GET"})
public class BlockchainAemBrowserServlet extends HttpServlet {

    private static final String GLOBAL_STORE_BASE_URL = System.getenv("PIKE_REPOSITORY_HTTP_URI");
    private static final String DEFAULT_BASE_URL = "http://oak-global-store:8090";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        PrintWriter out = response.getWriter();

        String baseUrl = GLOBAL_STORE_BASE_URL != null ? "http://" + GLOBAL_STORE_BASE_URL : DEFAULT_BASE_URL;

        try {
            // Check if GlobalStoreServer is reachable
            boolean healthy = checkHealth(baseUrl);

            // Build JSON response
            out.println("{");
            out.println("  \"globalStore\": {");
            out.println("    \"url\": \"" + baseUrl + "\",");
            out.println("    \"healthy\": " + healthy + ",");
            out.println("    \"protocol\": \"HTTP Segment Transfer\"");
            out.println("  },");

            if (healthy) {
                out.println("  \"status\": \"CONNECTED\",");
                out.println("  \"message\": \"Successfully connected to GlobalStoreServer!\",");
                out.println("  \"genesis\": {");
                out.println("    \"path\": \"/oak-chain/content/genesis\",");
                out.println("    \"message\": \"DO IT LIVE!\",");
                out.println("    \"description\": \"Blockchain AEM - Genesis block of the global TarMK chain\",");
                out.println("    \"author\": \"Blockchain AEM POC\",");
                out.println("    \"version\": \"1.0.0\",");
                out.println("    \"note\": \"Content is stored in data00001a.tar on GlobalStoreServer\"");
                out.println("  },");
                out.println("  \"capabilities\": {");
                out.println("    \"httpSegmentTransfer\": true,");
                out.println("    \"genesisContent\": true,");
                out.println("    \"byodModel\": true,");
                out.println("    \"consensusProtocol\": \"HTTP Segment Transfer (Cold Standby pattern)\"");
                out.println("  }");
            } else {
                out.println("  \"status\": \"DISCONNECTED\",");
                out.println("  \"message\": \"Could not connect to GlobalStoreServer. Is it running?\",");
                out.println("  \"troubleshooting\": {");
                out.println("    \"checkServer\": \"docker ps | grep oak-global-store\",");
                out.println("    \"checkHealth\": \"curl " + baseUrl + "/health\"");
                out.println("  }");
            }

            out.println("}");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            out.println("{");
            out.println("  \"status\": \"ERROR\",");
            out.println("  \"message\": \"" + e.getMessage().replace("\"", "\\\"") + "\"");
            out.println("}");
        }
    }

    /**
     * Check if GlobalStoreServer health endpoint is responding
     */
    private boolean checkHealth(String baseUrl) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(baseUrl + "/health");
            try (CloseableHttpResponse response = client.execute(request)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == 200) {
                    String body = EntityUtils.toString(response.getEntity());
                    return body.contains("\"status\":\"ok\"");
                }
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }
}
