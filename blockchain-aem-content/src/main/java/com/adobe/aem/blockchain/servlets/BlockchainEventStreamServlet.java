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
import org.json.JSONObject;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventConstants;
import org.osgi.service.event.EventHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Server-Sent Events (SSE) endpoint for real-time blockchain updates.
 * 🔥 Zero dependencies - pure Sling servlet magic!
 */
@Component(
    service = Servlet.class,
    immediate = true,
    property = {
        "sling.servlet.paths=/api/blockchain/events",
        "sling.servlet.methods=GET"
    }
)
public class BlockchainEventStreamServlet extends SlingAllMethodsServlet {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = LoggerFactory.getLogger(BlockchainEventStreamServlet.class);
    
    private final Map<String, PrintWriter> activeClients = new ConcurrentHashMap<>();
    private final AtomicLong clientIdCounter = new AtomicLong(0);
    private ServiceRegistration<EventHandler> eventHandlerRegistration;
    private BundleContext bundleContext;
    
    @Activate
    protected void activate(BundleContext context) {
        this.bundleContext = context;
        
        // Register as EventHandler for blockchain events
        Dictionary<String, Object> props = new Hashtable<>();
        props.put(EventConstants.EVENT_TOPIC, new String[] {
            "org/apache/sling/api/resource/*",
            "org/apache/jackrabbit/oak/segment/*"
        });
        
        EventHandler handler = this::handleOSGiEvent;
        eventHandlerRegistration = context.registerService(EventHandler.class, handler, props);
        
        log.info("🔥 SSE endpoint activated at /api/blockchain/events");
    }
    
    @Deactivate
    protected void deactivate() {
        if (eventHandlerRegistration != null) {
            eventHandlerRegistration.unregister();
        }
        activeClients.values().forEach(PrintWriter::close);
        activeClients.clear();
        log.info("SSE endpoint deactivated");
    }
    
    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response) 
            throws ServletException, IOException {
        
        String clientId = "sse-" + clientIdCounter.incrementAndGet();
        
        response.setContentType("text/event-stream");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-cache");
        response.setHeader("Connection", "keep-alive");
        
        PrintWriter writer = response.getWriter();
        activeClients.put(clientId, writer);
        log.info("📡 SSE client connected: {} (total: {})", clientId, activeClients.size());
        
        // Send welcome
        sendEvent(writer, "connected", new JSONObject()
            .put("clientId", clientId)
            .put("timestamp", System.currentTimeMillis())
            .toString());
        
        try {
            // Keep connection alive
            while (!Thread.currentThread().isInterrupted()) {
                Thread.sleep(30000);
                if (writer.checkError()) break;
                sendEvent(writer, "heartbeat", new JSONObject()
                    .put("timestamp", System.currentTimeMillis())
                    .toString());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            activeClients.remove(clientId);
            writer.close();
            log.info("📴 SSE client disconnected: {}", clientId);
        }
    }
    
    private void handleOSGiEvent(Event event) {
        try {
            JSONObject data = new JSONObject();
            data.put("topic", event.getTopic());
            data.put("timestamp", System.currentTimeMillis());
            
            for (String key : event.getPropertyNames()) {
                Object value = event.getProperty(key);
                if (value != null) {
                    data.put(key, value.toString());
                }
            }
            
            String eventType = determineEventType(event.getTopic(), data);
            broadcastToAll(eventType, data.toString());
            
        } catch (Exception e) {
            log.error("Error handling OSGi event", e);
        }
    }
    
    private void broadcastToAll(String eventType, String data) {
        activeClients.values().forEach(writer -> {
            try {
                sendEvent(writer, eventType, data);
            } catch (IOException e) {
                log.warn("Failed to send to client", e);
            }
        });
    }
    
    private void sendEvent(PrintWriter writer, String eventType, String data) throws IOException {
        writer.write("event: " + eventType + "\n");
        writer.write("data: " + data + "\n\n");
        writer.flush();
        if (writer.checkError()) {
            throw new IOException("Client disconnected");
        }
    }
    
    private String determineEventType(String topic, JSONObject data) {
        if (topic.contains("resource")) {
            String path = data.optString("path", "");
            if (path.contains("/epoch")) return "epoch";
            if (path.contains("/validators")) return "validator";
            if (path.contains("/proposals")) return "proposal";
            return "content";
        } else if (topic.contains("segment")) {
            return "sync";
        }
        return "update";
    }
}

