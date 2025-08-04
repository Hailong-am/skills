/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools.utils;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import lombok.Getter;
import lombok.extern.log4j.Log4j2;

/**
 * Drain3 - A fast and accurate log parser based on parse trees.
 * This is a Java implementation based on the Python Drain3 library.
 * 
 * Drain3 uses a fixed-depth parse tree to efficiently cluster log messages
 * based on their templates. It can extract parameters and create 
 * human-readable templates from log messages.
 */
@Log4j2
public class Drain3 {

    public static final String PARAMETER_MASK = "<*>";

    private final Drain3Config config;
    private final Drain3Node root;
    private final AtomicInteger clusterIdCounter;
    private final Map<String, LogCluster> clusterCache;
    private final Pattern delimiterPattern;

    // Statistics
    @Getter
    private final AtomicInteger totalProcessedMessages;
    @Getter
    private final AtomicInteger totalClusters;

    /**
     * Constructor with default configuration
     */
    public Drain3() {
        this(Drain3Config.builder().build());
    }

    /**
     * Constructor with custom configuration
     */
    public Drain3(Drain3Config config) {
        this.config = config;
        this.root = new Drain3Node(0);
        this.clusterIdCounter = new AtomicInteger(0);
        this.clusterCache = new ConcurrentHashMap<>();
        this.totalProcessedMessages = new AtomicInteger(0);
        this.totalClusters = new AtomicInteger(0);
        this.delimiterPattern = Pattern.compile(config.getDelimiters());
    }

    /**
     * Parse a log message and find/assign it to a cluster
     * 
     * @param logMessage The log message to parse
     * @return The LogCluster this message belongs to
     */
    public LogCluster parseLog(String logMessage) {
        return parseLog(logMessage, true);
    }
    
    /**
     * Parse a log message and optionally assign it to a cluster
     * 
     * @param logMessage The log message to parse
     * @param addToCluster Whether to add this message to the found cluster
     * @return The LogCluster this message belongs to or would belong to
     */
    public LogCluster parseLog(String logMessage, boolean addToCluster) {
        if (logMessage == null || logMessage.trim().isEmpty()) {
            log.warn("Empty log message provided");
            return null;
        }

        log.debug("Parsing log message: {}", logMessage);

        // Tokenize the log message
        List<String> tokens = tokenize(logMessage);
        if (tokens.isEmpty()) {
            log.warn("No tokens extracted from log message");
            return null;
        }

        log.debug("Tokens extracted: {}", tokens);

        // Find the best matching cluster
        LogCluster cluster = findBestMatch(tokens);

        if (cluster != null) {
            if (addToCluster) {
                // Add to existing cluster
                cluster.addLogMessage(logMessage);
                extractParameters(cluster, tokens);
                log.debug("Added to existing cluster: {}", cluster.getClusterId());
            }
        } else if (addToCluster) {
            // Create new cluster
            cluster = createNewCluster(tokens, logMessage);
            log.debug("Created new cluster: {}", cluster.getClusterId());
        }

        if (addToCluster) {
            totalProcessedMessages.incrementAndGet();
        }
        return cluster;
    }

    /**
     * Tokenize a log message into individual tokens
     */
    private List<String> tokenize(String logMessage) {
        String cleanedMessage = logMessage.trim();

        if (config.isPreFilterTokens()) {
            cleanedMessage = preFilter(cleanedMessage);
        }

        String[] rawTokens = delimiterPattern.split(cleanedMessage);
        List<String> tokens = new ArrayList<>();

        for (String token : rawTokens) {
            if (token != null && !token.trim().isEmpty()) {
                String processedToken = processToken(token.trim());
                if (!processedToken.isEmpty()) {
                    tokens.add(processedToken);
                }
            }
        }

        return tokens;
    }

    /**
     * Pre-filter the log message
     */
    private String preFilter(String message) {
        // Remove common prefixes like timestamps
        String filtered = message.replaceAll("^\\d{4}-\\d{2}-\\d{2}[\\sT]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{3})?", "");
        filtered = filtered.replaceAll("^\\[?\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{3})?\\]?", "");
        filtered = filtered.replaceAll("^\\d+", "");
        return filtered.trim();
    }

    /**
     * Process individual token
     */
    private String processToken(String token) {
        if (config.isRemoveDelimiters()) {
            token = token.replaceAll("[^\\w\\s]", "");
        }

        // Check if token is a number
        if (token.matches("^-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?$")) {
            return token; // Keep numbers as-is
        }

        // Check if token is a URL
        if (token.matches("https?://.*|ftp://.*|www\\..*")) {
            return "<URL>";
        }

        // Check if token is an IP address
        if (token.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")) {
            return "<IP>";
        }

        return token.toLowerCase();
    }

    /**
     * Find the best matching cluster for given tokens
     * This is equivalent to the Python tree_search method in Drain.py
     * 
     * @param tokens The tokens to match against existing clusters
     * @return The best matching cluster or null if no match found
     */
    public LogCluster findBestMatch(List<String> tokens) {
        // First level of tree is token count
        int tokenCount = tokens.size();
        Drain3Node tokenCountNode = root.getChild(String.valueOf(tokenCount));
        
        // No template with same token count yet
        if (tokenCountNode == null) {
            return null;
        }
        
        // Handle case of empty log string
        if (tokenCount == 0) {
            if (!tokenCountNode.getClusters().isEmpty()) {
                return tokenCountNode.getClusters().getFirst();
            }
            return null;
        }
        
        // Traverse the tree based on tokens up to maxDepth
        Drain3Node currentNode = tokenCountNode;
        int currentDepth = 1;
        
        for (int i = 0; i < Math.min(tokens.size(), config.getMaxDepth() - 1); i++) {
            // At max depth
            if (currentDepth >= config.getMaxDepth() - 1) {
                break;
            }
            
            // This is the last token
            if (currentDepth >= tokens.size()) {
                break;
            }
            
            String token = tokens.get(i);
            
            // Try exact match
            Drain3Node child = currentNode.getChild(token);
            if (child != null) {
                currentNode = child;
                currentDepth++;
                continue;
            }
            
            // Try wildcard match
            child = currentNode.getChild(PARAMETER_MASK);
            if (child != null) {
                currentNode = child;
                currentDepth++;
                continue;
            }
            
            // No match found at this level
            return null;
        }
        
        // Check clusters at the current node
        return findBestClusterInNode(currentNode, tokens);
    }

    /**
     * Find best matching cluster within a node
     */
    private LogCluster findBestClusterInNode(Drain3Node node, List<String> tokens) {
        LogCluster bestMatch = null;
        double bestSimilarity = 0.0;

        for (LogCluster cluster : node.getClusters()) {
            if (cluster.getLogTemplate() == null || cluster.getLogTemplate().size() != tokens.size()) {
                continue;
            }

            double similarity = calculateSimilarity(cluster.getLogTemplate(), tokens);
            if (similarity >= config.getSimilarityThreshold() && similarity > bestSimilarity) {
                bestSimilarity = similarity;
                bestMatch = cluster;
            }
        }

        return bestMatch;
    }

    /**
     * Calculate similarity between template and tokens
     */
    private double calculateSimilarity(List<String> template, List<String> tokens) {
        if (template.size() != tokens.size()) {
            return 0.0;
        }

        int matches = 0;
        int wildcards = 0;

        for (int i = 0; i < template.size(); i++) {
            String templateToken = template.get(i);
            String token = tokens.get(i);

            if (templateToken.equals(PARAMETER_MASK)) {
                wildcards++;
            } else if (templateToken.equals(token)) {
                matches++;
            }
        }

        return (double) (matches + wildcards) / template.size();
    }

    /**
     * Create a new cluster for tokens
     */
    private LogCluster createNewCluster(List<String> tokens, String logMessage) {
        // Build template by identifying parameters
        List<String> template = buildTemplate(tokens);

        LogCluster cluster = new LogCluster(template);
        cluster.addLogMessage(logMessage);
        extractParameters(cluster, tokens);

        // Add to tree
        addClusterToTree(cluster, tokens);

        totalClusters.incrementAndGet();
        return cluster;
    }

    /**
     * Build template by identifying parameters
     */
    private List<String> buildTemplate(List<String> tokens) {
        List<String> template = new ArrayList<>();

        for (String token : tokens) {
            if (shouldBeParameter(token)) {
                template.add(PARAMETER_MASK);
            } else {
                template.add(token);
            }
        }

        return template;
    }

    /**
     * Determine if a token should be treated as a parameter
     */
    private boolean shouldBeParameter(String token) {
        // Numbers
        if (token.matches("^-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?$")) {
            return true;
        }

        // UUID/GUID
        if (token.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
            return true;
        }

        // Long alphanumeric strings
        if (token.length() > 10 && token.matches("[a-zA-Z0-9]{10,}")) {
            return true;
        }

        // Hex strings
        if (token.matches("0x[0-9a-fA-F]+")) {
            return true;
        }

        return false;
    }

    /**
     * Add cluster to the tree
     * This is equivalent to the Python add_seq_to_prefix_tree method in Drain.py
     */
    private void addClusterToTree(LogCluster cluster, List<String> tokens) {
        int tokenCount = tokens.size();
        String tokenCountStr = String.valueOf(tokenCount);
        
        // First level of tree is token count
        Drain3Node firstLayerNode = root.getChild(tokenCountStr);
        if (firstLayerNode == null) {
            firstLayerNode = new Drain3Node(1, tokenCountStr);
            root.addChild(tokenCountStr, firstLayerNode);
        }
        
        Drain3Node currentNode = firstLayerNode;
        
        // Handle case of empty log string
        if (tokenCount == 0) {
            currentNode.addCluster(cluster);
            return;
        }
        
        int currentDepth = 1;
        for (int i = 0; i < tokens.size(); i++) {
            // If at max depth or this is the last token - add cluster to leaf node
            if (currentDepth >= config.getMaxDepth() - 1 || currentDepth >= tokenCount) {
                currentNode.addCluster(cluster);
                return;
            }
            
            String token = tokens.get(i);
            String nodeToken;
            
            // Use parameter mask for parameter tokens
            if (cluster.getLogTemplate().get(i).equals(PARAMETER_MASK)) {
                nodeToken = PARAMETER_MASK;
            } else {
                nodeToken = token;
            }
            
            // Check if token exists in child nodes
            Drain3Node childNode = currentNode.getChild(nodeToken);
            
            if (childNode == null) {
                // Token not matched in this layer
                if (shouldBeParameter(token)) {
                    // This token is a parameter candidate
                    childNode = currentNode.getChild(PARAMETER_MASK);
                    if (childNode == null) {
                        childNode = new Drain3Node(currentDepth + 1, PARAMETER_MASK);
                        currentNode.addChild(PARAMETER_MASK, childNode);
                    }
                } else {
                    // Regular token
                    if (currentNode.getChild(PARAMETER_MASK) != null) {
                        // Wildcard child exists
                        if (currentNode.getChildCount() < config.getMaxChildren()) {
                            childNode = new Drain3Node(currentDepth + 1, nodeToken);
                            currentNode.addChild(nodeToken, childNode);
                        } else {
                            childNode = currentNode.getChild(PARAMETER_MASK);
                        }
                    } else {
                        // No wildcard child
                        if (currentNode.getChildCount() + 1 < config.getMaxChildren()) {
                            childNode = new Drain3Node(currentDepth + 1, nodeToken);
                            currentNode.addChild(nodeToken, childNode);
                        } else if (currentNode.getChildCount() + 1 == config.getMaxChildren()) {
                            childNode = new Drain3Node(currentDepth + 1, PARAMETER_MASK);
                            currentNode.addChild(PARAMETER_MASK, childNode);
                        } else {
                            childNode = currentNode.getChild(PARAMETER_MASK);
                            if (childNode == null) {
                                // If still no wildcard child, create one
                                childNode = new Drain3Node(currentDepth + 1, PARAMETER_MASK);
                                currentNode.addChild(PARAMETER_MASK, childNode);
                            }
                        }
                    }
                }
            }
            
            currentNode = childNode;
            currentDepth++;
        }
        
        // Add cluster to the final node
        currentNode.addCluster(cluster);
    }

    /**
     * Extract parameters from log message
     */
    private void extractParameters(LogCluster cluster, List<String> tokens) {
        if (cluster.getLogTemplate() == null) {
            return;
        }

        Map<String, String> parameters = cluster.extractParameters(tokens);
        log.debug("Extracted parameters: {}", parameters);
    }

    /**
     * Get all clusters
     */
    public List<LogCluster> getAllClusters() {
        return root.getAllClusters();
    }

    /**
     * Get cluster by ID
     */
    public LogCluster getCluster(String clusterId) {
        return clusterCache.get(clusterId);
    }

    /**
     * Get total cluster size - sum of all log messages across all clusters
     */
    public int getTotalClusterSize() {
        int count = 0;
        for (LogCluster cluster : getAllClusters()) {
            count += cluster.getSize();
        }
        return count;
    }
    
    /**
     * Match a log message against existing clusters without adding it
     * 
     * @param logMessage The log message to match
     * @return The matching cluster or null if no match
     */
    public LogCluster match(String logMessage) {
        if (logMessage == null || logMessage.trim().isEmpty()) {
            return null;
        }
        
        List<String> tokens = tokenize(logMessage);
        if (tokens.isEmpty()) {
            return null;
        }
        
        return findBestMatch(tokens);
    }
    
    /**
     * Get cluster statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalProcessedMessages", totalProcessedMessages.get());
        stats.put("totalClusters", totalClusters.get());
        stats.put("currentClusters", getAllClusters().size());

        List<LogCluster> clusters = getAllClusters();
        if (!clusters.isEmpty()) {
            double avgSize = clusters.stream().mapToInt(LogCluster::getSize).average().orElse(0.0);
            stats.put("averageClusterSize", avgSize);

            int maxSize = clusters.stream().mapToInt(LogCluster::getSize).max().orElse(0);
            stats.put("maxClusterSize", maxSize);
        }

        return stats;
    }

    /**
     * Clear all clusters and reset parser
     */
    public void clear() {
        root.getClusters().clear();
        root.getChildren().clear();
        clusterCache.clear();
        totalProcessedMessages.set(0);
        totalClusters.set(0);
    }

    /**
     * Print tree structure for debugging
     */
    public void printTree() {
        log.info("Drain3 Tree Structure:\n{}\n", root.toTreeString(""));
    }

    /**
     * Get JSON representation of all clusters
     */
    public String toJson() {
        List<LogCluster> clusters = getAllClusters();
        StringBuilder json = new StringBuilder("[\n");

        for (int i = 0; i < clusters.size(); i++) {
            json.append("  ").append(clusters.get(i).toJson());
            if (i < clusters.size() - 1) {
                json.append(",");
            }
            json.append("\n");
        }

        json.append("]");
        return json.toString();
    }
}
