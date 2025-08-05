/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools.utils;

import java.util.regex.Pattern;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.LinkedHashMap;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;

/**
 * Default implementation of the Masker interface.
 * Provides common masking patterns for log messages.
 */
@Log4j2
public class DefaultMasker implements Masker {

    // Common mask patterns and their replacements
    private final List<MaskPattern> maskPatterns;
    
    /**
     * Inner class representing a pattern to mask and its replacement
     */
    private static class MaskPattern {
        private final Pattern pattern;
        private final String replacement;
        
        public MaskPattern(String regex, String replacement) {
            this.pattern = Pattern.compile(regex);
            this.replacement = replacement;
        }
        
        public String apply(String input) {
            return pattern.matcher(input).replaceAll(replacement);
        }
    }
    
    /**
     * Create a DefaultMasker with predefined common patterns
     */
    public DefaultMasker() {
        this.maskPatterns = new ArrayList<>();
        
        // Add common patterns
        // Date/time patterns
        addPattern("\\b(?:(?:\\d{4}[-/. ]\\d{1,2}[-/. ]\\d{1,2})|(?:\\d{1,2}[-/. ]\\d{1,2}[-/. ]\\d{4})|(?:\\d{1,2}(?:st|nd|rd|th)?\\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\\s,.]+\\d{4}))(?:(?:[T\\s]\\d{1,2}:\\d{2}(?::\\d{2})?(?:\\.\\d+)?)?(?:\\s*(?:AM|PM|am|pm))?(?:\\s*(?:Z|UTC|GMT|[+-]\\d{1,4}(?::?\\d{2})?)?)?)\\b", "<DATETIME>");
        addPattern("\\b\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{3})?\\b", "<TIME>");
        
        // IP addresses
        addPattern("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "<IP>");
        
        // UUIDs
        addPattern("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b", "<UUID>");
        
        // Common hexadecimal patterns (like memory addresses)
        addPattern("\\b0x[0-9a-fA-F]+\\b", "<HEX>");
        
        // URLs
        addPattern("https?://[^\\s]+", "<URL>");
        
        // Email addresses
        addPattern("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "<EMAIL>");
        
        // Long numbers (likely IDs)
        addPattern("\\b\\d{10,}\\b", "<ID>");
    }
    
    /**
     * Create a DefaultMasker with custom patterns
     * 
     * @param customPatterns Map of regex patterns to their replacements
     */
    public DefaultMasker(Map<String, String> customPatterns) {
        this();
        
        // Add custom patterns
        for (Map.Entry<String, String> entry : customPatterns.entrySet()) {
            addPattern(entry.getKey(), entry.getValue());
        }
    }
    
    /**
     * Add a new pattern to the masker
     * 
     * @param regex The regular expression to match
     * @param replacement The replacement string
     */
    public void addPattern(String regex, String replacement) {
        this.maskPatterns.add(new MaskPattern(regex, replacement));
    }
    
    @Override
    public String mask(String logMessage) {
        if (logMessage == null || logMessage.isEmpty()) {
            return logMessage;
        }
        
        String maskedMessage = logMessage;
        
        // Apply each pattern in order
        for (MaskPattern pattern : maskPatterns) {
            maskedMessage = pattern.apply(maskedMessage);
        }
        
        return maskedMessage;
    }
}