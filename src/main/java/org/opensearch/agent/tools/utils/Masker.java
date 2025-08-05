/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools.utils;

/**
 * Interface for masking log messages before tokenization in Drain3.
 * Implementations can provide different masking strategies based on requirements.
 */
public interface Masker {
    
    /**
     * Mask a log message by replacing specific patterns with mask tokens.
     * 
     * @param logMessage The raw log message to mask
     * @return The masked log message
     */
    String mask(String logMessage);
}