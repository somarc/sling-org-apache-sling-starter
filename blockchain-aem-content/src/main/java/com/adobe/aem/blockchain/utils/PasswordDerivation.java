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
package com.adobe.aem.blockchain.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Utility for deriving deterministic passwords from Ethereum wallet addresses.
 * 
 * <p>After verifying a signature proves ownership of a wallet's private key,
 * we derive a deterministic password using PBKDF2. This allows standard Oak
 * JAAS authentication without custom LoginModules.</p>
 * 
 * <p><strong>Security Model:</strong></p>
 * <ul>
 *   <li>Signature verification proves private key ownership (cryptographic proof)</li>
 *   <li>Derived password enables Oak JAAS authentication (standard path)</li>
 *   <li>Server-side salt prevents rainbow table attacks</li>
 *   <li>PBKDF2 with 10,000 iterations (OWASP minimum)</li>
 * </ul>
 * 
 * @since 2025-11-30
 */
public class PasswordDerivation {
    
    private static final Logger LOG = LoggerFactory.getLogger(PasswordDerivation.class);
    
    /**
     * Server-side secret salt for password derivation.
     * 
     * <p><strong>Configuration:</strong></p>
     * <ul>
     *   <li>Environment variable: {@code BLOCKCHAIN_AEM_PASSWORD_SALT}</li>
     *   <li>Recommended: Use secret management system (Vault, AWS Secrets Manager)</li>
     *   <li>Security: Keep this secret! If leaked, passwords can be derived.</li>
     * </ul>
     */
    private static final String SERVER_SECRET = getServerSecret();
    
    /**
     * PBKDF2 iteration count (OWASP recommended minimum: 10,000).
     */
    private static final int ITERATIONS = 10000;
    
    /**
     * Output key length in bits (256-bit = 32 bytes).
     */
    private static final int KEY_LENGTH = 256;
    
    /**
     * Derive a deterministic password from a wallet address.
     * 
     * <p>This method uses PBKDF2-HMAC-SHA256 to derive a password from:</p>
     * <ul>
     *   <li>Input: Wallet address (0x...)</li>
     *   <li>Salt: Server-side secret</li>
     *   <li>Iterations: 10,000 (OWASP minimum)</li>
     *   <li>Output: 256-bit key, Base64-encoded</li>
     * </ul>
     * 
     * <p><strong>Important:</strong> The same wallet address always produces
     * the same password (deterministic). This is essential for authentication
     * to work across multiple login attempts.</p>
     * 
     * @param walletAddress The Ethereum wallet address (e.g., 0x17d5bf1a...)
     * @return Base64-encoded password hash (44 characters)
     * @throws IllegalStateException if server secret not configured
     * @throws RuntimeException if password derivation fails
     */
    public static String derivePassword(String walletAddress) {
        if (SERVER_SECRET == null || SERVER_SECRET.isEmpty()) {
            throw new IllegalStateException(
                "BLOCKCHAIN_AEM_PASSWORD_SALT environment variable not set. " +
                "This is required for password derivation."
            );
        }
        
        if (walletAddress == null || walletAddress.isEmpty()) {
            throw new IllegalArgumentException("Wallet address cannot be null or empty");
        }
        
        try {
            LOG.debug("🔐 Deriving password for wallet: {}", 
                walletAddress.substring(0, Math.min(10, walletAddress.length())) + "...");
            
            // Create PBKDF2 key spec
            PBEKeySpec spec = new PBEKeySpec(
                walletAddress.toCharArray(),  // Password input
                SERVER_SECRET.getBytes(),      // Salt
                ITERATIONS,                    // Iteration count
                KEY_LENGTH                     // Output key length
            );
            
            // Generate key using PBKDF2-HMAC-SHA256
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            // Encode to Base64 for storage/transport
            String derivedPassword = Base64.getEncoder().encodeToString(hash);
            
            LOG.debug("✅ Password derived successfully (length: {} chars)", derivedPassword.length());
            
            return derivedPassword;
            
        } catch (NoSuchAlgorithmException e) {
            LOG.error("❌ PBKDF2 algorithm not available", e);
            throw new RuntimeException("Password derivation failed: algorithm not found", e);
            
        } catch (InvalidKeySpecException e) {
            LOG.error("❌ Invalid key specification", e);
            throw new RuntimeException("Password derivation failed: invalid key spec", e);
        }
    }
    
    /**
     * Get server secret from environment variable.
     * 
     * <p><strong>Configuration Priority:</strong></p>
     * <ol>
     *   <li>Environment variable: {@code BLOCKCHAIN_AEM_PASSWORD_SALT}</li>
     *   <li>System property: {@code blockchain.aem.password.salt}</li>
     *   <li>Default (DEV ONLY): Hardcoded fallback with warning</li>
     * </ol>
     * 
     * @return Server secret for password derivation
     */
    private static String getServerSecret() {
        // Try environment variable first (production)
        String secret = System.getenv("BLOCKCHAIN_AEM_PASSWORD_SALT");
        if (secret != null && !secret.isEmpty()) {
            LOG.info("✅ Using password salt from environment variable");
            return secret;
        }
        
        // Try system property (testing)
        secret = System.getProperty("blockchain.aem.password.salt");
        if (secret != null && !secret.isEmpty()) {
            LOG.info("✅ Using password salt from system property");
            return secret;
        }
        
        // Fallback for development (WARN: not for production!)
        LOG.warn("⚠️  USING DEFAULT PASSWORD SALT FOR DEVELOPMENT");
        LOG.warn("⚠️  Set BLOCKCHAIN_AEM_PASSWORD_SALT environment variable for production!");
        return "blockchain-aem-dev-salt-DO-NOT-USE-IN-PRODUCTION";
    }
    
    /**
     * Validate that password derivation is properly configured.
     * 
     * @return true if configuration is valid
     */
    public static boolean isConfigured() {
        try {
            String secret = getServerSecret();
            return secret != null && !secret.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
}

