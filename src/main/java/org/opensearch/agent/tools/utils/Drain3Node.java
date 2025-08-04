/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * Node in the Drain3 parse tree structure.
 * Based on the Node class from Drain3 Python implementation.
 */
@Data
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class Drain3Node {

    /**
     * Depth of this node in the tree
     */
    @EqualsAndHashCode.Include
    @ToString.Include
    private final int depth;

    /**
     * Token at this node
     */
    private String token;

    /**
     * Child nodes mapping token to child
     */
    private ConcurrentMap<String, Drain3Node> children;

    /**
     * Log clusters at this node
     */
    private List<LogCluster> clusters;

    /**
     * Constructor
     */
    public Drain3Node(int depth) {
        this.depth = depth;
        this.children = new ConcurrentHashMap<>();
        this.clusters = new ArrayList<>();
    }

    /**
     * Constructor with token
     */
    public Drain3Node(int depth, String token) {
        this(depth);
        this.token = token;
    }

    /**
     * Get child node by token
     */
    public Drain3Node getChild(String token) {
        return children.get(token);
    }

    /**
     * Add child node
     */
    public void addChild(String token, Drain3Node child) {
        children.put(token, child);
    }

    /**
     * Remove child node
     */
    public void removeChild(String token) {
        children.remove(token);
    }

    /**
     * Check if this node has children
     */
    public boolean hasChildren() {
        return !children.isEmpty();
    }

    /**
     * Get number of children
     */
    public int getChildCount() {
        return children.size();
    }

    /**
     * Get all child tokens
     */
    public List<String> getChildTokens() {
        return new ArrayList<>(children.keySet());
    }

    /**
     * Add a log cluster to this node
     */
    public void addCluster(LogCluster cluster) {
        clusters.add(cluster);
    }

    /**
     * Remove a log cluster from this node
     */
    public void removeCluster(LogCluster cluster) {
        clusters.remove(cluster);
    }

    /**
     * Get cluster by template
     */
    public LogCluster getClusterByTemplate(List<String> template) {
        for (LogCluster cluster : clusters) {
            if (cluster.getLogTemplate() != null && cluster.getLogTemplate().equals(template)) {
                return cluster;
            }
        }
        return null;
    }

    /**
     * Find best matching cluster for tokens
     */
    public LogCluster findBestMatchingCluster(List<String> tokens, double similarityThreshold) {
        LogCluster bestMatch = null;
        double bestSimilarity = 0.0;

        for (LogCluster cluster : clusters) {
            if (cluster.matches(tokens, similarityThreshold)) {
                double similarity = calculateSimilarity(cluster.getLogTemplate(), tokens);
                if (similarity > bestSimilarity) {
                    bestSimilarity = similarity;
                    bestMatch = cluster;
                }
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
        for (int i = 0; i < template.size(); i++) {
            if (template.get(i).equals(tokens.get(i)) || template.get(i).equals(Drain3.PARAMETER_MASK)) {
                matches++;
            }
        }

        return (double) matches / template.size();
    }

    /**
     * Get all clusters under this node (including children)
     */
    public List<LogCluster> getAllClusters() {
        List<LogCluster> allClusters = new ArrayList<>(clusters);

        for (Drain3Node child : children.values()) {
            allClusters.addAll(child.getAllClusters());
        }

        return allClusters;
    }

    /**
     * Get total number of clusters under this node
     */
    public int getTotalClusterCount() {
        int count = clusters.size();
        for (Drain3Node child : children.values()) {
            count += child.getTotalClusterCount();
        }
        return count;
    }

    /**
     * Check if this is a leaf node
     */
    public boolean isLeaf() {
        return children.isEmpty();
    }

    /**
     * Clear all clusters from this node
     */
    public void clearClusters() {
        clusters.clear();
    }

    /**
     * Get node statistics
     */
    public String getStats() {
        return String
            .format(
                "Depth: %d, Token: %s, Children: %d, Clusters: %d, Total Clusters: %d",
                depth,
                token != null ? token : "ROOT",
                children.size(),
                clusters.size(),
                getTotalClusterCount()
            );
    }

    /**
     * Serialize node to string representation
     */
    public String toTreeString(String prefix) {
        StringBuilder sb = new StringBuilder();
        sb
            .append(prefix)
            .append("├── ")
            .append(token != null ? token : "ROOT")
            .append(" (depth: ")
            .append(depth)
            .append(", clusters: ")
            .append(clusters.size())
            .append(")\n");

        String childPrefix = prefix + "│   ";
        for (Drain3Node child : children.values()) {
            sb.append(child.toTreeString(childPrefix));
        }

        return sb.toString();
    }
}
