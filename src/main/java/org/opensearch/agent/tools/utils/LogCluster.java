/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * Represents a cluster of log messages that share the same template.
 * Based on LogCluster from Drain3 Python implementation.
 */
@Data
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class LogCluster {

    /**
     * Unique identifier for the cluster
     */
    @EqualsAndHashCode.Include
    @ToString.Include
    private final String clusterId;

    /**
     * The log template (pattern) for this cluster
     */
    private List<String> logTemplate;

    /**
     * Number of log messages in this cluster
     */
    private AtomicInteger size;

    /**
     * Sample log messages for this cluster
     */
    private List<String> logMessages;

    /**
     * Parameters extracted from log messages
     */
    private Map<String, List<String>> parameters;

    /**
     * Example log message
     */
    private String exampleLogMessage;

    /**
     * Constructor
     */
    public LogCluster() {
        this.clusterId = java.util.UUID.randomUUID().toString();
        this.size = new AtomicInteger(0);
        this.logMessages = new ArrayList<>();
        this.parameters = new ConcurrentHashMap<>();
    }

    /**
     * Constructor with template
     */
    public LogCluster(List<String> logTemplate) {
        this();
        this.logTemplate = new ArrayList<>(logTemplate);
    }

    /**
     * Add a log message to this cluster
     */
    public void addLogMessage(String logMessage) {
        logMessages.add(logMessage);
        size.incrementAndGet();

        if (exampleLogMessage == null) {
            exampleLogMessage = logMessage;
        }
    }

    /**
     * Get the current size of the cluster
     */
    public int getSize() {
        return size.get();
    }

    /**
     * Get the log template as a string
     */
    public String getTemplateString() {
        return String.join(" ", logTemplate);
    }

    /**
     * Check if this cluster matches the given tokens based on similarity threshold
     */
    public boolean matches(List<String> tokens, double similarityThreshold) {
        if (logTemplate == null || tokens.size() != logTemplate.size()) {
            return false;
        }

        int matches = 0;
        for (int i = 0; i < logTemplate.size(); i++) {
            String templateToken = logTemplate.get(i);
            String token = tokens.get(i);

            if (templateToken.equals(token) || templateToken.equals(Drain3.PARAMETER_MASK)) {
                matches++;
            }
        }

        double similarity = (double) matches / logTemplate.size();
        return similarity >= similarityThreshold;
    }

    /**
     * Extract parameters from a log message based on the template
     */
    public Map<String, String> extractParameters(List<String> tokens) {
        Map<String, String> extractedParams = new ConcurrentHashMap<>();

        if (logTemplate == null || tokens.size() != logTemplate.size()) {
            return extractedParams;
        }

        for (int i = 0; i < logTemplate.size(); i++) {
            String templateToken = logTemplate.get(i);
            String token = tokens.get(i);

            if (templateToken.equals(Drain3.PARAMETER_MASK) && !token.equals(templateToken)) {
                String paramName = "param_" + i;
                extractedParams.put(paramName, token);

                // Store parameter for analysis
                parameters.computeIfAbsent(paramName, k -> new ArrayList<>()).add(token);
            }
        }

        return extractedParams;
    }

    /**
     * Get parameter statistics
     */
    public Map<String, Integer> getParameterStats() {
        Map<String, Integer> stats = new ConcurrentHashMap<>();
        for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
            stats.put(entry.getKey(), entry.getValue().size());
        }
        return stats;
    }

    /**
     * Get the most recent log message
     */
    public String getLatestLogMessage() {
        if (logMessages.isEmpty()) {
            return "";
        }
        return logMessages.get(logMessages.size() - 1);
    }

    /**
     * Get cluster summary information
     */
    public String getSummary() {
        return String.format("Cluster ID: %s, Size: %d, Template: %s", clusterId, getSize(), getTemplateString());
    }

    /**
     * Get JSON representation of the cluster
     */
    public String toJson() {
        return String
            .format(
                "{\"cluster_id\":\"%s\",\"size\":%d,\"template\":\"%s\",\"example\":\"%s\"}",
                clusterId,
                getSize(),
                getTemplateString().replace("\"", "\\\""),
                exampleLogMessage != null ? exampleLogMessage.replace("\"", "\\\"") : ""
            );
    }
}
