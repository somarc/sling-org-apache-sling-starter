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
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Ethereum signature verification utility using web3j.
 * 
 * <p>Manually computes the Ethereum personal message hash to ensure
 * exact compatibility with MetaMask's personal_sign.</p>
 * 
 * @since 2025-11-30
 */
public class SignatureVerifier {
    
    private static final Logger LOG = LoggerFactory.getLogger(SignatureVerifier.class);
    
    /**
     * The Ethereum signed message prefix (EIP-191).
     */
    private static final String PERSONAL_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";
    
    /**
     * Verify an Ethereum personal_sign signature matches the claimed address.
     * 
     * @param message   The original message that was signed
     * @param signature The hex-encoded signature (0x... 132 characters)
     * @param address   The claimed wallet address (0x... 42 characters)
     * @return true if signature is valid and matches address, false otherwise
     */
    public static boolean verify(String message, String signature, String address) {
        LOG.info("🔐 Verifying Ethereum signature (REAL VERIFICATION)...");
        LOG.info("   Message length: {} chars", message != null ? message.length() : 0);
        LOG.info("   Message (escaped): {}", message != null ? message.replace("\n", "\\n").replace("\r", "\\r") : null);
        
        // Validate inputs
        if (message == null || message.isEmpty()) {
            LOG.error("❌ Message cannot be null or empty");
            return false;
        }
        
        if (signature == null || !signature.startsWith("0x") || signature.length() != 132) {
            LOG.error("❌ Invalid signature format (expected 0x + 130 hex chars, got length {})", 
                signature != null ? signature.length() : 0);
            return false;
        }
        
        if (address == null || !address.startsWith("0x") || address.length() != 42) {
            LOG.error("❌ Invalid address format (expected 0x + 40 hex chars)");
            return false;
        }
        
        try {
            // Step 1: Convert message to UTF-8 bytes
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            LOG.info("   Message bytes length: {}", messageBytes.length);
            
            // Step 2: Compute Ethereum personal message hash (EIP-191)
            // Format: keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
            String prefixWithLength = PERSONAL_MESSAGE_PREFIX + messageBytes.length;
            byte[] prefixBytes = prefixWithLength.getBytes(StandardCharsets.UTF_8);
            
            // Concatenate prefix + message
            byte[] fullMessage = new byte[prefixBytes.length + messageBytes.length];
            System.arraycopy(prefixBytes, 0, fullMessage, 0, prefixBytes.length);
            System.arraycopy(messageBytes, 0, fullMessage, prefixBytes.length, messageBytes.length);
            
            // Compute keccak256 hash
            byte[] messageHash = Hash.sha3(fullMessage);
            LOG.info("   Message hash: {}", Numeric.toHexString(messageHash));
            
            // Step 3: Parse signature into r, s, v components
            byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
            
            if (signatureBytes.length != 65) {
                LOG.error("❌ Signature must be 65 bytes, got {}", signatureBytes.length);
                return false;
            }
            
            byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
            byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
            byte v = signatureBytes[64];
            
            LOG.info("   Raw v value: {}", v & 0xFF);
            LOG.info("   r: {}", Numeric.toHexString(r));
            LOG.info("   s: {}", Numeric.toHexString(s));
            
            // Step 4: Try recovery with both v values
            // MetaMask can return v as 0, 1, 27, or 28
            for (int recId = 0; recId < 4; recId++) {
                try {
                    // Recover public key from signature
                    BigInteger publicKey = Sign.recoverFromSignature(
                        recId,
                        new org.web3j.crypto.ECDSASignature(
                            new BigInteger(1, r),
                            new BigInteger(1, s)
                        ),
                        messageHash
                    );
                    
                    if (publicKey != null) {
                        String recoveredAddress = "0x" + Keys.getAddress(publicKey);
                        LOG.info("   Recovered address (recId={}): {}", recId, recoveredAddress);
                        
                        if (recoveredAddress.equalsIgnoreCase(address)) {
                            LOG.info("✅ SIGNATURE VERIFIED! Address {} owns the private key", address);
                            LOG.info("   Recovery ID that worked: {}", recId);
                            return true;
                        }
                    }
                } catch (Exception e) {
                    LOG.debug("   Recovery with recId={} failed: {}", recId, e.getMessage());
                }
            }
            
            // No recovery ID worked
            LOG.warn("❌ SIGNATURE MISMATCH!");
            LOG.warn("   Claimed address: {}", address);
            LOG.warn("   No recovery ID produced matching address");
            LOG.warn("   This signature was NOT created by the claimed address");
            
            return false;
            
        } catch (Exception e) {
            LOG.error("❌ Signature verification failed: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Verify signature with additional timestamp check.
     */
    public static boolean verifyWithTimestamp(String message, String signature, String address, long maxAgeMs) {
        if (!verify(message, signature, address)) {
            return false;
        }
        
        try {
            int timestampIndex = message.indexOf("Timestamp:");
            if (timestampIndex != -1) {
                String timestampStr = message.substring(timestampIndex + 10).trim();
                StringBuilder sb = new StringBuilder();
                for (char c : timestampStr.toCharArray()) {
                    if (Character.isDigit(c)) {
                        sb.append(c);
                    } else {
                        break;
                    }
                }
                
                long timestamp = Long.parseLong(sb.toString());
                long age = System.currentTimeMillis() - timestamp;
                
                if (age > maxAgeMs) {
                    LOG.warn("❌ Message too old: {} ms", age);
                    return false;
                }
                
                LOG.info("✅ Timestamp valid: {} ms old", age);
            }
        } catch (Exception e) {
            LOG.warn("⚠️  Could not parse timestamp: {}", e.getMessage());
        }
        
        return true;
    }
}
