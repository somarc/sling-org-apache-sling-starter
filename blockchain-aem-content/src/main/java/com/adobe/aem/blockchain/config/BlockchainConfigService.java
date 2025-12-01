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
package com.adobe.aem.blockchain.config;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.osgi.service.metatype.annotations.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OSGi configuration service for Blockchain AEM client settings.
 * 
 * This is the single source of truth for the Sling client's blockchain mode.
 * Independent from validator configuration - each component knows its own mode.
 */
@Component(service = BlockchainConfigService.class, immediate = true)
@Designate(ocd = BlockchainConfigService.Config.class)
public class BlockchainConfigService {

    private static final Logger log = LoggerFactory.getLogger(BlockchainConfigService.class);

    @ObjectClassDefinition(
        name = "Blockchain AEM Configuration",
        description = "Configure blockchain mode and validator connection for this Sling client"
    )
    public @interface Config {
        
        @AttributeDefinition(
            name = "Blockchain Mode",
            description = "Operating mode: mock (simulated), sepolia (testnet), or mainnet (production)",
            options = {
                @Option(label = "Mock (Simulated)", value = "mock"),
                @Option(label = "Sepolia Testnet", value = "sepolia"),
                @Option(label = "Ethereum Mainnet", value = "mainnet")
            }
        )
        String mode() default "mock";
        
        @AttributeDefinition(
            name = "Validator URL",
            description = "URL of the validator to connect to (e.g., http://localhost:8090)"
        )
        String validatorUrl() default "http://localhost:8090";
        
        @AttributeDefinition(
            name = "Requires MetaMask",
            description = "Whether MetaMask is required for publishing (false in mock mode)"
        )
        boolean requiresMetaMask() default false;
        
        @AttributeDefinition(
            name = "Smart Contract Address",
            description = "Ethereum smart contract address (ValidatorPayment contract)"
        )
        String contractAddress() default "0x7fcEc350268F5482D04eb4B229A0679374906732";
    }

    private String mode;
    private String validatorUrl;
    private boolean requiresMetaMask;
    private String contractAddress;

    @Activate
    @Modified
    protected void activate(Config config) {
        this.mode = config.mode();
        this.validatorUrl = config.validatorUrl();
        this.requiresMetaMask = config.requiresMetaMask();
        this.contractAddress = config.contractAddress();
        
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        log.info("🔧 Blockchain AEM Configuration");
        log.info("   Mode: {}", getModeDisplayName());
        log.info("   Validator: {}", validatorUrl);
        log.info("   Requires MetaMask: {}", requiresMetaMask);
        log.info("   Contract: {}", contractAddress);
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    public String getMode() {
        return mode;
    }

    public String getValidatorUrl() {
        return validatorUrl;
    }

    public boolean isRequiresMetaMask() {
        return requiresMetaMask;
    }

    public String getContractAddress() {
        return contractAddress;
    }

    public String getModeDisplayName() {
        switch (mode) {
            case "mock":
                return "🎭 MOCK MODE";
            case "sepolia":
                return "✅ SEPOLIA TESTNET";
            case "mainnet":
                return "🔥 ETHEREUM MAINNET";
            default:
                return "UNKNOWN MODE";
        }
    }

    public String getBadgeColor() {
        switch (mode) {
            case "mock":
                return "#fbbf24"; // Yellow/amber
            case "sepolia":
                return "#10b981"; // Green
            case "mainnet":
                return "#ef4444"; // Red (danger!)
            default:
                return "#6b7280"; // Gray
        }
    }
}

