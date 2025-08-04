/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools.utils;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration class for Drain3 log parsing algorithm.
 * Based on the Python Drain3 implementation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Drain3Config {

    /**
     * Maximum depth of the parse tree
     */
    @Builder.Default
    private int maxDepth = 4;

    /**
     * Maximum number of children for a node in the parse tree
     */
    @Builder.Default
    private int maxChildren = 100;

    /**
     * Similarity threshold for matching log templates
     */
    @Builder.Default
    private double similarityThreshold = 0.4;

    /**
     * Maximum number of wildcards allowed in a template
     */
    @Builder.Default
    private int maxWildcards = 3;

    /**
     * Whether to use regex for token matching
     */
    @Builder.Default
    private boolean useRegex = false;

    /**
     * Delimiters for tokenizing log messages
     */
    @Builder.Default
    private String delimiters = "\\s+";

    /**
     * Whether to remove delimiters from tokens
     */
    @Builder.Default
    private boolean removeDelimiters = true;

    /**
     * Whether to save parameters in clusters
     */
    @Builder.Default
    private boolean saveParameters = true;

    /**
     * Whether to mask parameters
     */
    @Builder.Default
    private boolean maskParameters = false;

    /**
     * Parameter masking string
     */
    @Builder.Default
    private String parameterMask = "<*>";

    /**
     * Minimum length for a token to be considered as parameter
     */
    @Builder.Default
    private int minParameterLength = 2;

    /**
     * Whether to perform pre-filtering of tokens
     */
    @Builder.Default
    private boolean preFilterTokens = true;

    /**
     * Maximum cluster size before splitting
     */
    @Builder.Default
    private int maxClusterSize = 1000;

    /**
     * Whether to perform post-processing of templates
     */
    @Builder.Default
    private boolean postProcessTemplates = true;
}
