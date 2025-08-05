/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.tools;

import static org.opensearch.agent.tools.utils.HierarchicalAgglomerativeClustering.calculateCosineSimilarity;
import static org.opensearch.agent.tools.utils.ToolHelper.getPPLTransportActionListener;
import static org.opensearch.ml.common.utils.StringUtils.gson;

import org.opensearch.agent.tools.utils.DefaultMasker;
import org.opensearch.agent.tools.utils.Drain3;
import org.opensearch.agent.tools.utils.Drain3Config;
import org.opensearch.agent.tools.utils.LogCluster;
import org.opensearch.search.SearchHit;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.math3.ml.clustering.CentroidCluster;
import org.apache.commons.math3.ml.clustering.DoublePoint;
import org.apache.commons.math3.ml.clustering.KMeansPlusPlusClusterer;
import org.apache.commons.math3.ml.distance.DistanceMeasure;
import org.json.JSONObject;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.agent.tools.utils.HierarchicalAgglomerativeClustering;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.core.common.Strings;
import org.opensearch.ml.common.spi.tools.Tool;
import org.opensearch.ml.common.spi.tools.ToolAnnotation;
import org.opensearch.sql.plugin.transport.PPLQueryAction;
import org.opensearch.sql.plugin.transport.TransportPPLQueryRequest;
import org.opensearch.sql.ppl.domain.PPLQueryRequest;
import org.opensearch.transport.client.Client;

import com.google.common.collect.ImmutableMap;
import com.google.gson.reflect.TypeToken;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;

/**
 * Usage:
 * 1. Register agent:
 * POST /_plugins/_ml/agents/_register
 * {
 *   "name": "LogPatternAnalysis",
 *   "type": "flow",
 *   "tools": [
 *     {
 *       "name": "log_pattern_analysis_tool",
 *       "type": "LogPatternAnalysisTool",
 *       "parameters": {
 *       }
 *     }
 *   ]
 * }
 * 2. Execute agent:
 * POST /_plugins/_ml/agents/{agent_id}/_execute
 * {
 *   "parameters": {
 *     "index": "ss4o_logs-otel-2025.06.24",
 *     "logFieldName": "body",
 *     "traceFieldName": "traceId",
 *     "baseTimeRangeStart": "2025-06-24T07:33:05Z",
 *     "baseTimeRangeEnd": "2025-06-24T07:51:27Z",
 *     "selectionTimeRangeStart": "2025-06-24T07:50:26.999999999Z",
 *     "selectionTimeRangeEnd": "2025-06-24T07:55:56Z"
 *   }
 * }
 * 3. Result: a list of selection traceId
 * {
 *   "inference_results": [
 *     {
 *       "output": [
 *         {
 *           "name": "response",
 *           "result": """["34398ae14561313af05f1b02179aaf45","de0f0fa00083a5c54b8b732ae70ea158"]"""
 *         }
 *       ]
 *     }
 *   ]
 * }
 */
@Log4j2
@Setter
@Getter
@ToolAnnotation(LogPatternAnalysisTool.TYPE)
public class LogPatternAnalysisTool implements Tool {
    public static final String TYPE = "LogPatternAnalysisTool";

    // Constants
    private static final String DEFAULT_DESCRIPTION =
        "This is a tool used to detect selection log patterns by the Drain3 log clustering algorithm or to detect selection log sequences by the log clustering algorithm.";
    private static final double LOG_VECTORS_CLUSTERING_THRESHOLD = 0.5;
    private static final double LOG_PATTERN_THRESHOLD = 0.75;
    private static final double LOG_PATTERN_LIFT = 3;
    private static final String DEFAULT_TIME_FIELD = "@timestamp";
    
    // Drain3 configuration
    private static final double DRAIN3_SIMILARITY_THRESHOLD = 0.5;
    private static final int DRAIN3_MAX_DEPTH = 5;
    private static final int DRAIN3_MAX_CHILDREN = 100;
    private static final int MAX_LOG_FETCH_SIZE = 10000;
    
    // Drain3 instance for log pattern analysis
    private final Drain3 drain3;
    
    // Removed regex pattern since we're using cluster IDs

    /**
     * Parameter class to hold analysis parameters with validation
     */
    private static class AnalysisParameters {
        final String index;
        final String timeField;
        final String logFieldName;
        final String traceFieldName;
        final String baseTimeRangeStart;
        final String baseTimeRangeEnd;
        final String selectionTimeRangeStart;
        final String selectionTimeRangeEnd;

        AnalysisParameters(Map<String, String> parameters) {
            this.index = parameters.getOrDefault("index", "");
            this.timeField = parameters.getOrDefault("timeField", DEFAULT_TIME_FIELD);
            this.logFieldName = parameters.getOrDefault("logFieldName", "message");
            this.traceFieldName = parameters.getOrDefault("traceFieldName", "");
            this.baseTimeRangeStart = parameters.getOrDefault("baseTimeRangeStart", "");
            this.baseTimeRangeEnd = parameters.getOrDefault("baseTimeRangeEnd", "");
            this.selectionTimeRangeStart = parameters.getOrDefault("selectionTimeRangeStart", "");
            this.selectionTimeRangeEnd = parameters.getOrDefault("selectionTimeRangeEnd", "");
        }

        private void validate() {
            if (Strings.isEmpty(index)
                || Strings.isEmpty(timeField)
                || Strings.isEmpty(logFieldName)
                || Strings.isEmpty(selectionTimeRangeStart)
                || Strings.isEmpty(selectionTimeRangeEnd)) {
                throw new IllegalArgumentException(
                    "Invalid parameters: index, timeField, logFieldName, selectionTimeRangeStart, selectionTimeRangeEnd are required!"
                );
            }
        }

        boolean hasBaseTime() {
            return !Strings.isEmpty(baseTimeRangeStart) && !Strings.isEmpty(baseTimeRangeEnd);
        }

        boolean hasTraceField() {
            return !Strings.isEmpty(traceFieldName);
        }
    }

    /**
     * Result class for pattern analysis
     */
    private record PatternAnalysisResult(Map<String, Set<String>> tracePatternMap, Map<String, Set<String>> patternCountMap,
        Map<String, Double> patternValues, int totalTraceCount) {
    }

    private record PatternDiff(String pattern, Double base, Double selection, Double lift) {
    }

    private record PatternWithSamples(String pattern, double count, List<?> sampleLogs) {
    }

    // Instance fields
    @Setter
    @Getter
    private String name = TYPE;
    @Getter
    @Setter
    private String description = DEFAULT_DESCRIPTION;
    @Getter
    private String version;
    private Client client;

    public LogPatternAnalysisTool(Client client) {
        this.client = client;
        
        // Create a DefaultMasker for log preprocessing
        DefaultMasker defaultMasker = new DefaultMasker();
        
        // Add any custom patterns if needed
        // For example, masking timestamps, IPs, etc. is already handled by DefaultMasker
        
        // Initialize Drain3 with custom configuration including the masker
        Drain3Config drain3Config = Drain3Config.builder()
            .delimiters("[\\s+]")
            .similarityThreshold(DRAIN3_SIMILARITY_THRESHOLD)
            .maxDepth(DRAIN3_MAX_DEPTH)
            .maxChildren(DRAIN3_MAX_CHILDREN)
            .masker(defaultMasker)
            .build();
            
        this.drain3 = new Drain3(drain3Config);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    @Override
    public void setAttributes(Map<String, Object> map) {

    }

    @Override
    public boolean validate(Map<String, String> map) {
        try {
            new AnalysisParameters(map).validate();
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @Override
    public <T> void run(Map<String, String> parameters, ActionListener<T> listener) {
        try {
            log.info("Starting log pattern analysis with parameters: {}", parameters.keySet());
            AnalysisParameters params = new AnalysisParameters(parameters);

            if (params.hasTraceField() && params.hasBaseTime()) {
                log.info("Performing log sequence analysis for index: {}", params.index);
                logSequenceAnalysis(params, listener);
            } else if (params.hasBaseTime()) {
                log.info("Performing log pattern analysis for index: {}", params.index);
                logPatternDiffAnalysis(params, listener);
            } else {
                logInsight(params, listener);
            }
        } catch (IllegalArgumentException e) {
            log.error("Invalid parameters for LogPatternAnalysisTool: {}", e.getMessage());
            listener.onFailure(e);
        } catch (Exception e) {
            log.error("Unexpected error in LogPatternAnalysisTool", e);
            listener.onFailure(new RuntimeException("Failed to execute log pattern analysis", e));
        }
    }

    private <T> void logSequenceAnalysis(AnalysisParameters params, ActionListener<T> listener) {
        log
            .debug(
                "Starting log sequence analysis for time ranges: base[{} - {}], selection[{} - {}]",
                params.baseTimeRangeStart,
                params.baseTimeRangeEnd,
                params.selectionTimeRangeStart,
                params.selectionTimeRangeEnd
            );

        // Step 1: Analyze base time range
        analyzeBaseTimeRange(params, ActionListener.wrap(baseResult -> {
            log.info("Base time range analysis completed, found {} traces", baseResult.totalTraceCount);

            // Step 2: Analyze selection time range
            analyzeSelectionTimeRange(params, ActionListener.wrap(selectionResult -> {
                log.info("Selection time range analysis completed, found {} traces", selectionResult.totalTraceCount);

                // Step 3: Generate comparison result
                generateSequenceComparisonResult(baseResult, selectionResult, listener);
            }, listener::onFailure));
        }, this::handleSearchError));
    }

    /**
     * Analyze logs in the base time range using Drain3
     */
    private <T> void analyzeBaseTimeRange(AnalysisParameters params, ActionListener<PatternAnalysisResult> listener) {
        log.debug("Analyzing base time range logs from index {}", params.index);
        
        // Create search request for logs with trace field
        SearchRequest searchRequest = new SearchRequest(params.index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        
        // Build time range query
        searchSourceBuilder.query(
            QueryBuilders.boolQuery()
                .must(QueryBuilders.rangeQuery(params.timeField)
                    .from(params.baseTimeRangeStart, true)
                    .to(params.baseTimeRangeEnd, true))
                .must(QueryBuilders.existsQuery(params.traceFieldName))
        );
        
        searchSourceBuilder.size(MAX_LOG_FETCH_SIZE);
        searchSourceBuilder.sort(params.timeField, SortOrder.ASC);
        searchSourceBuilder.fetchSource(new String[]{params.logFieldName, params.traceFieldName, params.timeField}, null);
        
        searchRequest.source(searchSourceBuilder);
        
        // Execute search
        client.search(searchRequest, ActionListener.wrap(searchResponse -> {
            try {
                // Process search results into trace pattern map
                Map<String, Set<String>> tracePatternMap = new HashMap<>();
                Map<String, Set<String>> patternCountMap = new HashMap<>();
                Map<String, String> rawPatternCache = new HashMap<>();

                for (SearchHit hit : searchResponse.getHits()) {
                    Map<String, Object> source = hit.getSourceAsMap();
                    if (source.containsKey(params.logFieldName) && source.containsKey(params.traceFieldName)) {
                        String traceId = source.get(params.traceFieldName).toString();
                        String logMessage = source.get(params.logFieldName).toString();
                        
                        // Process with Drain3
                        LogCluster cluster = drain3.parseLog(logMessage);
                        String clusterId = cluster.getClusterId();
                        
                        // Using clusterId directly - no need for post-processing
                        String simplifiedPattern = clusterId;
                        
                        // Store in trace pattern map
                        tracePatternMap.computeIfAbsent(traceId, k -> new LinkedHashSet<>()).add(simplifiedPattern);
                        patternCountMap.computeIfAbsent(simplifiedPattern, k -> new HashSet<>()).add(traceId);
                    }
                }
                
                // Calculate pattern vectors
                Map<String, Double> patternValues = vectorizePattern(patternCountMap, tracePatternMap.size());
                
                PatternAnalysisResult result = new PatternAnalysisResult(
                    tracePatternMap, patternCountMap, patternValues, tracePatternMap.size());
                    
                listener.onResponse(result);
                
            } catch (Exception e) {
                log.error("Failed to process base time range logs", e);
                listener.onFailure(new RuntimeException("Failed to process base time range analysis", e));
            }
        }, listener::onFailure));
    }

    /**
     * Analyze logs in the selection time range using Drain3
     * Uses the same Drain3 instance as the base time range for consistent patterns
     */
    private <T> void analyzeSelectionTimeRange(AnalysisParameters params, ActionListener<PatternAnalysisResult> listener) {
        log.debug("Analyzing selection time range logs from index {}", params.index);
        
        // Create search request for logs with trace field
        SearchRequest searchRequest = new SearchRequest(params.index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        
        // Build time range query
        searchSourceBuilder.query(
            QueryBuilders.boolQuery()
                .must(QueryBuilders.rangeQuery(params.timeField)
                    .from(params.selectionTimeRangeStart, true)
                    .to(params.selectionTimeRangeEnd, true))
                .must(QueryBuilders.existsQuery(params.traceFieldName))
        );
        
        searchSourceBuilder.size(MAX_LOG_FETCH_SIZE);
        searchSourceBuilder.sort(params.timeField, SortOrder.ASC);
        searchSourceBuilder.fetchSource(new String[]{params.logFieldName, params.traceFieldName, params.timeField}, null);
        
        searchRequest.source(searchSourceBuilder);
        
        // Execute search
        client.search(searchRequest, ActionListener.wrap(searchResponse -> {
            try {
                // Process search results into trace pattern map
                Map<String, Set<String>> tracePatternMap = new HashMap<>();
                Map<String, Set<String>> patternCountMap = new HashMap<>();
                Map<String, String> rawPatternCache = new HashMap<>();
                
                for (SearchHit hit : searchResponse.getHits()) {
                    Map<String, Object> source = hit.getSourceAsMap();
                    if (source.containsKey(params.logFieldName) && source.containsKey(params.traceFieldName)) {
                        String traceId = source.get(params.traceFieldName).toString();
                        String logMessage = source.get(params.logFieldName).toString();
                        
                        // Process with Drain3 - using same instance as base time range
                        LogCluster cluster = drain3.parseLog(logMessage);
                        String clusterId = cluster.getClusterId();
                        
                        // Using clusterId directly - no need for post-processing
                        String simplifiedPattern = clusterId;
                        
                        // Store in trace pattern map
                        tracePatternMap.computeIfAbsent(traceId, k -> new LinkedHashSet<>()).add(simplifiedPattern);
                        patternCountMap.computeIfAbsent(simplifiedPattern, k -> new HashSet<>()).add(traceId);
                    }
                }
                
                // Calculate pattern vectors
                Map<String, Double> patternValues = vectorizePattern(patternCountMap, tracePatternMap.size());
                
                PatternAnalysisResult result = new PatternAnalysisResult(
                    tracePatternMap, patternCountMap, patternValues, tracePatternMap.size());
                    
                listener.onResponse(result);
                
            } catch (Exception e) {
                log.error("Failed to process selection time range logs", e);
                listener.onFailure(new RuntimeException("Failed to process selection time range analysis", e));
            }
        }, listener::onFailure));
    }



    private Map<String, Double> vectorizePattern(Map<String, Set<String>> patternCountMap, int totalTraceCount) {
        Map<String, Double> patternValues = new HashMap<>();

        for (Map.Entry<String, Set<String>> entry : patternCountMap.entrySet()) {
            String pattern = entry.getKey();
            Set<String> traceIds = entry.getValue();

            if (traceIds != null && !traceIds.isEmpty()) {
                // IDF calculation
                double idf = Math.log((double) totalTraceCount / traceIds.size());
                // Apply sigmoid function
                double value = 1.0 / (1.0 + Math.exp(-idf));
                patternValues.put(pattern, value);
            } else {
                patternValues.put(pattern, 0.0);
            }
        }

        return patternValues;
    }

    private <T> void generateSequenceComparisonResult(
        PatternAnalysisResult baseResult,
        PatternAnalysisResult selectionResult,
        ActionListener<T> listener
    ) {
        try {
            // Step 3: Build pattern index for vector construction
            Map<String, Integer> patternIndexMap = buildPatternIndex(baseResult, selectionResult);
            log.debug("Built pattern index with {} patterns", patternIndexMap.size());

            // Step 4: Build vectors for base time range
            Map<String, double[]> baseVectorMap = buildVectorMap(
                baseResult.tracePatternMap,
                baseResult.patternValues,
                patternIndexMap,
                false
            );

            // Step 5: Cluster base vectors and find centroids
            List<String> baseRepresentative = clusterLogVectorsAndGetRepresentative(baseVectorMap);

            // Step 6: Build vectors for selection time range
            Map<String, double[]> selectionVectorMap = buildVectorMap(
                selectionResult.tracePatternMap,
                selectionResult.patternValues,
                patternIndexMap,
                true,
                baseResult.patternCountMap,
                selectionResult.patternCountMap
            );

            // Step 7: Find selection centroids
            List<String> selectionRepresentative = clusterLogVectorsAndGetRepresentative(selectionVectorMap);

            List<String> selction = filterSelectionCentroids(
                baseRepresentative,
                selectionRepresentative,
                baseVectorMap,
                selectionVectorMap
            );

            log.info("Identified {} selection centroids from {} candidates", selction.size(), selectionRepresentative.size());

            // Generate final result
            Map<String, Map<String, String>> result = buildFinalResult(
                baseRepresentative,
                selction,
                baseResult.tracePatternMap,
                selectionResult.tracePatternMap
            );


            listener.onResponse((T) gson.toJson(result));

        } catch (Exception e) {
            log.error("Failed to generate sequence comparison result", e);
            listener.onFailure(new RuntimeException("Failed to generate comparison result", e));
        }
    }

    private Map<String, Integer> buildPatternIndex(PatternAnalysisResult baseResult, PatternAnalysisResult selectionResult) {
        Set<String> allPatterns = new HashSet<>(baseResult.patternCountMap.keySet());
        allPatterns.addAll(selectionResult.patternCountMap.keySet());

        List<String> sortedPatterns = new ArrayList<>(allPatterns);
        Collections.sort(sortedPatterns);

        // pattern and its index in a vector
        Map<String, Integer> patternIndexMap = new HashMap<>();
        for (int i = 0; i < sortedPatterns.size(); i++) {
            patternIndexMap.put(sortedPatterns.get(i), i);
        }

        return patternIndexMap;
    }

    private Map<String, double[]> buildVectorMap(
        Map<String, Set<String>> tracePatternMap,
        Map<String, Double> patternValues,
        Map<String, Integer> patternIndexMap,
        boolean isSelection,
        Map<String, Set<String>>... additionalPatternMaps
    ) {
        Map<String, double[]> vectorMap = new HashMap<>();
        int vectorSize = patternIndexMap.size();

        for (Map.Entry<String, Set<String>> entry : tracePatternMap.entrySet()) {
            String traceId = entry.getKey();
            Set<String> patterns = entry.getValue();
            // for trace with single pattern, we have already done the analysis in pattern difference
            if (patterns.size() ==1) continue;
            double[] vector = new double[vectorSize];

            for (String pattern : patterns) {
                Integer index = patternIndexMap.get(pattern);
                if (index != null) {
                    double baseValue = 0.5 * patternValues.getOrDefault(pattern, 0.0);

                    if (isSelection && additionalPatternMaps.length >= 2) {
                        // Add existence weight for selection patterns
                        Map<String, Set<String>> basePatterns = additionalPatternMaps[0];
                        Map<String, Set<String>> selectionPatterns = additionalPatternMaps[1];

                        int existenceWeight = (selectionPatterns.containsKey(pattern) && !basePatterns.containsKey(pattern)) ? 1 : 0;
                        vector[index] = baseValue + 0.5 * existenceWeight;
                    } else {
                        vector[index] = baseValue;
                    }
                }
            }

            vectorMap.put(traceId, vector);
        }

        return vectorMap;
    }

    private List<String> filterSelectionCentroids(
        List<String> baseCentroids,
        List<String> selectionCandidates,
        Map<String, double[]> baseVectorMap,
        Map<String, double[]> selectionVectorMap
    ) {
        List<String> selectionCentroids = new ArrayList<>();

        for (String candidate : selectionCandidates) {
            boolean isSelection = true;
            double[] candidateVector = selectionVectorMap.get(candidate);

            if (candidateVector == null) {
                log.warn("No vector found for selection candidate: {}", candidate);
                continue;
            }

            for (String baseCentroid : baseCentroids) {
                double[] baseVector = baseVectorMap.get(baseCentroid);
                if (baseVector != null && calculateCosineSimilarity(baseVector, candidateVector) > LOG_VECTORS_CLUSTERING_THRESHOLD) {
                    isSelection = false;
                    break;
                }
            }

            if (isSelection) {
                selectionCentroids.add(candidate);
            }
        }

        return selectionCentroids;
    }

    private Map<String, Map<String, String>> buildFinalResult(
        List<String> baseCentroids,
        List<String> selectionCentroids,
        Map<String, Set<String>> baseTracePatternMap,
        Map<String, Set<String>> selectionTracePatternMap
    ) {
        Map<String, String> baseSequences = new HashMap<>();
        for (String centroid : baseCentroids) {
            String patterns =
                    baseTracePatternMap.get(centroid).stream().sequential()
                            .filter((id) -> !Objects.isNull(id) && this.drain3.getCluster(id) != null)
                            .map((id) -> this.drain3.getCluster(id).getTemplateString())
                            .collect(Collectors.joining(", ", "[", "]"));
            baseSequences.put(centroid, patterns);
        }

        Map<String, String> selectionSequences = new HashMap<>();
        for (String centroid : selectionCentroids) {
            String patterns = selectionTracePatternMap.get(centroid)
                    .stream().map((id) -> this.drain3.getCluster(id).getTemplateString())
                    .collect(Collectors.joining(", ", "[", "]"));
            selectionSequences.put(centroid, patterns);
        }

        Map<String, Map<String, String>> result = new HashMap<>();
        result.put("BASE", baseSequences);
        result.put("EXCEPTIONAL", selectionSequences);

        return result;
    }

    /**
     * Fetch logs from an index based on time range and process them with Drain3
     * 
     * @param index Index name to fetch logs from
     * @param timeField Field name for timestamp
     * @param logFieldName Field name containing log messages
     * @param startTime Start time for logs (ISO format)
     * @param endTime End time for logs (ISO format)
     * @param listener Listener to call when complete with Map of patterns to counts
     */
    private void fetchLogsAndProcess(
        String index,
        String timeField,
        String logFieldName,
        String startTime,
        String endTime,
        ActionListener<Map<String, Double>> listener
    ) {
        log.info("Fetching logs from index {} in time range {} to {}", index, startTime, endTime);
        
        // Create search request
        SearchRequest searchRequest = new SearchRequest(index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        
        // Build time range query
        RangeQueryBuilder rangeQuery = QueryBuilders.rangeQuery(timeField)
            .from(startTime, true)
            .to(endTime, true);
            
        searchSourceBuilder.query(rangeQuery);
        searchSourceBuilder.size(MAX_LOG_FETCH_SIZE);  // Fetch a large batch
        searchSourceBuilder.sort(timeField, SortOrder.ASC);
        searchSourceBuilder.fetchSource(new String[]{logFieldName}, null);
        
        searchRequest.source(searchSourceBuilder);
        
        // Execute search
        client.search(searchRequest, ActionListener.wrap(searchResponse -> {
            try {
                Map<String, Double> patternMap = new HashMap<>();
                Map<LogCluster, Integer> clusterCountMap = new HashMap<>();
                
                // Process logs with Drain3
                for (SearchHit hit : searchResponse.getHits().getHits()) {
                    Map<String, Object> source = hit.getSourceAsMap();
                    if (source.containsKey(logFieldName)) {
                        String logMessage = source.get(logFieldName).toString();
                        
                        // Process with Drain3
                        LogCluster cluster = drain3.parseLog(logMessage);
                        
                        // Count occurrences
                        clusterCountMap.put(cluster, clusterCountMap.getOrDefault(cluster, 0) + 1);
                    }
                }
                
                // Convert clusters to pattern map
                for (Map.Entry<LogCluster, Integer> entry : clusterCountMap.entrySet()) {
                    LogCluster cluster = entry.getKey();
                    int count = entry.getValue();
                    
                    patternMap.put(cluster.getTemplateString(), (double) count);
                }
                
                log.info("Processed {} logs, found {} patterns", searchResponse.getHits().getTotalHits().toString(), patternMap.size());
                
                listener.onResponse(patternMap);
                
            } catch (Exception e) {
                log.error("Error processing logs with Drain3", e);
                listener.onFailure(e);
            }
        }, e -> {
            log.error("Failed to fetch logs from index {}", index, e);
            listener.onFailure(e);
        }));
    }
    
    private <T> void logPatternDiffAnalysis(AnalysisParameters params, ActionListener<T> listener) {
        log
            .debug(
                "Starting log pattern analysis for time ranges: base[{} - {}], selection[{} - {}]",
                params.baseTimeRangeStart,
                params.baseTimeRangeEnd,
                params.selectionTimeRangeStart,
                params.selectionTimeRangeEnd
            );

        // Step 1: Generate log patterns for baseline time range using Drain3
        log.debug("Fetching and processing base time range logs");
        fetchLogsAndProcess(
            params.index,
            params.timeField,
            params.logFieldName,
            params.baseTimeRangeStart,
            params.baseTimeRangeEnd,
            ActionListener.wrap(basePatterns -> {
            try {
                mergeSimilarPatterns(basePatterns);
                log.debug("Base patterns processed: {} patterns", basePatterns.size());

                // Step 2: Generate log patterns for selection time range using Drain3
                // Note: We're using the same Drain3 instance to maintain consistent patterns
                log.debug("Fetching and processing selection time range logs");
                fetchLogsAndProcess(
                    params.index,
                    params.timeField,
                    params.logFieldName,
                    params.selectionTimeRangeStart,
                    params.selectionTimeRangeEnd,
                    ActionListener.wrap(selectionPatterns -> {
                    try {
                        mergeSimilarPatterns(selectionPatterns);
                        log.debug("Selection patterns processed: {} patterns", selectionPatterns.size());

                        // Step 3: Calculate pattern differences
                        List<PatternDiff> patternDifferences = calculatePatternDifferences(basePatterns, selectionPatterns);

                        Map<String, Object> finalResult = new HashMap<>();
                        finalResult.put("patternMapDifference", patternDifferences);

                        log.info("Pattern analysis completed: {} differences found", patternDifferences.size());
                        log.debug("finalResult={}", gson.toJson(finalResult));
                        listener.onResponse((T) gson.toJson(finalResult));

                    } catch (Exception e) {
                        log.error("Failed to process selection pattern response", e);
                        listener.onFailure(new RuntimeException("Failed to process selection patterns", e));
                    }
                }, listener::onFailure));

            } catch (Exception e) {
                log.error("Failed to process base pattern response", e);
                listener.onFailure(new RuntimeException("Failed to process base patterns", e));
            }
        }, this::handleSearchError));
    }

    /**
     * Fetch logs with error keywords and process them with Drain3
     * 
     * @param index Index name to fetch logs from
     * @param timeField Field name for timestamp
     * @param logFieldName Field name containing log messages
     * @param startTime Start time for logs (ISO format)
     * @param endTime End time for logs (ISO format) 
     * @param errorKeywords List of error keywords to match
     * @param listener Listener to call when complete with Map of patterns to sample logs
     */
    private void fetchErrorLogsAndProcess(
        String index,
        String timeField,
        String logFieldName,
        String startTime,
        String endTime,
        List<String> errorKeywords,
        ActionListener<List<PatternWithSamples>> listener
    ) {
        log.info("Fetching error logs from index {} in time range {} to {}", index, startTime, endTime);
        
        // Create search request
        SearchRequest searchRequest = new SearchRequest(index);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        
        // Build query - time range and error keywords
        StringBuilder queryBuilder = new StringBuilder();
        for (int i = 0; i < errorKeywords.size(); i++) {
            if (i > 0) queryBuilder.append(" OR ");
            queryBuilder.append(logFieldName).append(":").append(errorKeywords.get(i));
        }
        
        // Combine with time range
        searchSourceBuilder.query(
            QueryBuilders.boolQuery()
                .must(QueryBuilders.rangeQuery(timeField)
                    .from(startTime, true)
                    .to(endTime, true))
                .must(QueryBuilders.queryStringQuery(queryBuilder.toString()))
        );
        
        searchSourceBuilder.size(MAX_LOG_FETCH_SIZE);  // Fetch a large batch
        searchSourceBuilder.sort(timeField, SortOrder.DESC);  // Most recent first
        searchSourceBuilder.fetchSource(new String[]{logFieldName}, null);
        
        searchRequest.source(searchSourceBuilder);
        
        // Execute search
        client.search(searchRequest, ActionListener.wrap(searchResponse -> {
            try {
                Map<String, LogCluster> patternMap = new HashMap<>();
                Map<String, List<String>> patternSamples = new HashMap<>();
                int maxSamplesPerPattern = 2;  // Keep only 2 sample logs per pattern
                
                // Process logs with Drain3
                for (SearchHit hit : searchResponse.getHits().getHits()) {
                    Map<String, Object> source = hit.getSourceAsMap();
                    if (source.containsKey(logFieldName)) {
                        String logMessage = source.get(logFieldName).toString();
                        
                        // Process with Drain3
                        LogCluster cluster = drain3.parseLog(logMessage);
                        String clusterId = cluster.getClusterId();
                        
                        // Store cluster and samples
                        patternMap.putIfAbsent(clusterId, cluster);
                        
                        // Store sample logs (up to max)
                        List<String> samples = patternSamples.computeIfAbsent(clusterId, k -> new ArrayList<>());
                        if (samples.size() < maxSamplesPerPattern) {
                            samples.add(logMessage);
                        }
                    }
                }
                
                // Convert to result format
                List<PatternWithSamples> results = new ArrayList<>();
                for (Map.Entry<String, LogCluster> entry : patternMap.entrySet()) {
                    String clusterId = entry.getKey();
                    LogCluster cluster = entry.getValue();
                    double count = cluster.getSize();
                    List<String> samples = patternSamples.getOrDefault(clusterId, Collections.emptyList());
                    
                    // Use template string for display in results
                    results.add(new PatternWithSamples(cluster.getTemplateString(), count, samples));
                }
                
                // Sort by count (descending)
                results.sort((a, b) -> Double.compare(b.count(), a.count()));
                
                // Limit to top 5
                if (results.size() > 5) {
                    results = results.subList(0, 5);
                }
                
                log.info("Processed {} error logs, found {} patterns", 
                    searchResponse.getHits().getTotalHits().toString(), results.size());
                
                listener.onResponse(results);
                
            } catch (Exception e) {
                log.error("Error processing error logs with Drain3", e);
                listener.onFailure(e);
            }
        }, e -> {
            log.error("Failed to fetch error logs from index {}", index, e);
            listener.onFailure(e);
        }));
    }
    
    private <T> void logInsight(AnalysisParameters params, ActionListener<T> listener) {
        List<String> errorKeywords = List
            .of(
                "error",
                "err",
                "exception",
                "failed",
                "failure",
                "timeout",
                "panic",
                "fatal",
                "critical",
                "severe",
                "abort",
                "aborted",
                "aborting",
                "crash",
                "crashed",
                "broken",
                "corrupt",
                "corrupted",
                "invalid",
                "malformed",
                "unprocessable",
                "denied",
                "forbidden",
                "unauthorized",
                "conflict",
                "deadlock",
                "overflow",
                "underflow",
                "resource_exhausted",
                "out_of_resources",
                "quota_exceeded",
                "rate_limit_exceeded",
                "throttled",
                "disk_full",
                "no_space_left",
                "insufficient_storage",
                "dependency",
                "retrying",
                "cold_start",
                "warmup",
                "saturation",
                "backpressure",
                "queue_full",
                "degraded",
                "unexpected",
                "unusual",
                "missing",
                "stale",
                "expired",
                "mismatch",
                "validation_failed",
                "schema_violation",
                "timeout_approaching",
                "deadline_exceeded",
                "retry_backoff",
                "invalid_token",
                "expired_token",
                "token_revoked",
                "authentication_failed",
                "auth_error",
                "permission_denied",
                "role_mismatch",
                "audit_failure",
                "access_violation"
            );

        // Process logs with error keywords using Drain3
        fetchErrorLogsAndProcess(
            params.index,
            params.timeField,
            params.logFieldName,
            params.selectionTimeRangeStart,
            params.selectionTimeRangeEnd,
            errorKeywords,
            ActionListener.wrap(logInsights -> {
            try {
                Map<String, Object> finalResult = new HashMap<>();
                finalResult.put("logInsights", logInsights);
                listener.onResponse((T) gson.toJson(finalResult));
            } catch (Exception e) {
                log.error("Failed to process base pattern response", e);
                listener.onFailure(new RuntimeException("Failed to process base patterns", e));
            }
        }, this::handleSearchError));
    }

    /**
     * Calculate pattern differences between baseline and selection time ranges
     */
    private List<PatternDiff> calculatePatternDifferences(Map<String, Double> basePatterns, Map<String, Double> selectionPatterns) {
        List<PatternDiff> differences = new ArrayList<>();

        double selectionTotal = selectionPatterns.values().stream().mapToDouble(Double::doubleValue).sum();
        double baseTotal = basePatterns.values().stream().mapToDouble(Double::doubleValue).sum();

        for (Map.Entry<String, Double> entry : selectionPatterns.entrySet()) {
            String pattern = entry.getKey();
            double selectionCount = entry.getValue();

            if (basePatterns.containsKey(pattern)) {
                double baseCount = basePatterns.get(pattern);
                double lift = (selectionCount / selectionTotal) / (baseCount / baseTotal);

                if (lift < 1) {
                    lift = 1.0 / lift;
                }

                if (lift > LOG_PATTERN_LIFT) {
                    differences.add(new PatternDiff(pattern, baseCount / baseTotal, selectionCount / selectionTotal, lift));
                }
            } else {
                // Pattern only exists in selection time range
                differences.add(new PatternDiff(pattern, 0.0, selectionCount / selectionTotal, null));
                log.debug("New selection pattern detected: {} (count: {})", pattern, selectionCount);
            }
        }

        return differences;
    }


    /**
     * Handle search errors with appropriate exception
     */
    private void handleSearchError(Throwable error) {
        log.error("OpenSearch search failed: {}", error.getMessage());
        if (error.toString().contains("IndexNotFoundException")) {
            throw new IllegalArgumentException("Index not found: " + error.getMessage(), error);
        } else {
            throw new RuntimeException("OpenSearch search failed", error);
        }
    }

    // Using cluster IDs directly - no need for similarity comparison
    private void mergeSimilarPatterns(Map<String, Double> patternMap) {
        // Since we're using cluster IDs which are already unique identifiers
        // for each log pattern cluster, we don't need to merge similar patterns
        log.debug("Using cluster IDs directly: {} clusters", patternMap.size());
    }


    /**
     * Cluster log vectors using a two-phase approach:
     * 1. K-means clustering to split large datasets into smaller groups (500-1000 data points each)
     * 2. Hierarchical clustering within each K-means cluster for fine-grained clustering
     * 
     * @param logVectors Map of trace IDs to their vector representations
     * @return List of trace IDs representing the centroids of each cluster
     */
    private List<String> clusterLogVectorsAndGetRepresentative(Map<String, double[]> logVectors) {
        if (logVectors.isEmpty()) {
            return new ArrayList<>();
        }

        log.debug("Starting two-phase clustering for {} log vectors", logVectors.size());

        // Convert map to arrays for processing
        double[][] vectors = new double[logVectors.size()][];
        Map<Integer, String> indexTraceIdMap = new HashMap<>();
        int i = 0;
        for (Map.Entry<String, double[]> entry : logVectors.entrySet()) {
            vectors[i] = entry.getValue();
            indexTraceIdMap.put(i, entry.getKey());
            i++;
        }

        List<String> finalCentroids = new ArrayList<>();

        // Phase 1: K-means clustering for large datasets
        if (logVectors.size() > 1000) {
            log.debug("Large dataset detected ({}), applying K-means pre-clustering", logVectors.size());

            // Calculate optimal number of K-means clusters (target 500-1000 points per cluster)
            int targetClusterSize = 500;
            int numKMeansClusters = (logVectors.size() + (targetClusterSize - 1)) / targetClusterSize;

            log.debug("Using {} K-means clusters for pre-clustering", numKMeansClusters);

            try {
                log.info("Starting performKMeansClustering");
                List<List<Integer>> kMeansClusters = performKMeansClustering(vectors, numKMeansClusters);
                log.info("Completing performKMeansClustering");

                // Phase 2: Apply hierarchical clustering within each K-means cluster
                for (int clusterIdx = 0; clusterIdx < kMeansClusters.size(); clusterIdx++) {
                    List<Integer> kMeansCluster = kMeansClusters.get(clusterIdx);
                    log.info("kMeansCluster " + kMeansCluster.size());

                    if (kMeansCluster.isEmpty()) {
                        continue;
                    }

                    if (kMeansCluster.size() == 1) {
                        // Single point cluster - add directly
                        finalCentroids.add(indexTraceIdMap.get(kMeansCluster.getFirst()));
                        continue;
                    }

                    if (kMeansCluster.size() > 500) {
                        log.info("the cluster size is greater than 500, perform partitioning");
                        List<String> clusterCentroids = performHierarchicalClusteringOfPartition(kMeansCluster, vectors, indexTraceIdMap);
                        finalCentroids.addAll(clusterCentroids);
                        continue;
                    }

                    log.debug("Applying hierarchical clustering to K-means cluster {} with {} points", clusterIdx, kMeansCluster.size());

                    // Extract vectors for this K-means cluster
                    double[][] clusterVectors = new double[kMeansCluster.size()][];
                    Map<Integer, String> clusterIndexTraceIdMap = new HashMap<>();

                    for (int j = 0; j < kMeansCluster.size(); j++) {
                        int originalIndex = kMeansCluster.get(j);
                        clusterVectors[j] = vectors[originalIndex];
                        clusterIndexTraceIdMap.put(j, indexTraceIdMap.get(originalIndex));
                    }

                    // Apply hierarchical clustering within this K-means cluster
                    log.info("Starting performHierarchicalClustering");
                    List<String> clusterCentroids = performHierarchicalClustering(clusterVectors, clusterIndexTraceIdMap);

                    log.info("Completing performHierarchicalClustering");
                    finalCentroids.addAll(clusterCentroids);
                }

            } catch (Exception e) {
                log.warn("K-means clustering failed, falling back to hierarchical clustering only: {}", e.getMessage());
                // Fallback to hierarchical clustering only
                finalCentroids = performHierarchicalClustering(vectors, indexTraceIdMap);
            }

        } else {
            // Small dataset - use hierarchical clustering directly
            log.debug("Small dataset ({}), using hierarchical clustering only", logVectors.size());
            finalCentroids = performHierarchicalClustering(vectors, indexTraceIdMap);
        }

        log
            .debug(
                "Two-phase clustering completed: {} input vectors -> {} representative centroids",
                logVectors.size(),
                finalCentroids.size()
            );

        return finalCentroids;
    }

    /**
     * Perform K-means clustering using Apache Commons Math3
     * 
     * @param vectors Input vectors for clustering
     * @param numClusters Number of K-means clusters
     * @return List of clusters, each containing indices of points in that cluster
     */
    private List<List<Integer>> performKMeansClustering(double[][] vectors, int numClusters) {
        try {
            KMeansPlusPlusClusterer<DoublePoint> clusterer = new KMeansPlusPlusClusterer<>(
                numClusters,
                300,
                (DistanceMeasure) (a, b) -> 1 - calculateCosineSimilarity(a, b)
            );

            // Convert vectors to DoublePoint objects
            List<DoublePoint> points = new ArrayList<>();
            for (double[] vector : vectors) {
                points.add(new DoublePoint(vector));
            }

            // Perform K-means clustering
            List<CentroidCluster<DoublePoint>> clusters = clusterer.cluster(points);

            // Convert results back to our format
            List<List<Integer>> result = new ArrayList<>();
            for (CentroidCluster<DoublePoint> cluster : clusters) {
                List<Integer> clusterIndices = new ArrayList<>();
                for (DoublePoint point : cluster.getPoints()) {
                    // Find the original index of this point
                    for (int i = 0; i < vectors.length; i++) {
                        if (Arrays.equals(vectors[i], point.getPoint())) {
                            clusterIndices.add(i);
                            break;
                        }
                    }
                }
                if (!clusterIndices.isEmpty()) {
                    result.add(clusterIndices);
                }
            }

            return result;

        } catch (Exception e) {
            log.error("K-means clustering failed: {}", e.getMessage(), e);
            throw new RuntimeException("K-means clustering failed", e);
        }
    }

    /**
     * Perform hierarchical clustering on a subset of vectors
     * 
     * @param vectors Input vectors for clustering
     * @param indexTraceIdMap Mapping from vector index to trace ID
     * @return List of trace IDs representing cluster centroids
     */
    private List<String> performHierarchicalClustering(double[][] vectors, Map<Integer, String> indexTraceIdMap) {
        List<String> centroids = new ArrayList<>();

        if (vectors.length == 0) {
            return centroids;
        }

        if (vectors.length == 1) {
            centroids.add(indexTraceIdMap.get(0));
            return centroids;
        }

        try {
            HierarchicalAgglomerativeClustering hac = new HierarchicalAgglomerativeClustering(vectors);
            List<HierarchicalAgglomerativeClustering.ClusterNode> clusters = hac
                .fit(HierarchicalAgglomerativeClustering.LinkageMethod.COMPLETE, LOG_VECTORS_CLUSTERING_THRESHOLD);

            for (HierarchicalAgglomerativeClustering.ClusterNode cluster : clusters) {
                int centroidIndex = hac.getClusterCentroid(cluster);
                centroids.add(indexTraceIdMap.get(centroidIndex));
            }

        } catch (Exception e) {
            log.error("Hierarchical clustering failed: {}", e.getMessage(), e);
            // Fallback: return first point as representative
            centroids.add(indexTraceIdMap.get(0));
        }

        return centroids;
    }

    /**
     * If the first stage K-means clustering results exceed 500 clusters, implement batch processing and merge the results.
     * @param kMeansCluster Clustering results from the first stage.
     * @param vectors List of vectors by index.
     * @param indexTraceIdMap Map of index to their trace id.
     * @return
     */
    private List<String> performHierarchicalClusteringOfPartition(
        List<Integer> kMeansCluster,
        double[][] vectors,
        Map<Integer, String> indexTraceIdMap
    ) {
        List<List<Integer>> partition = new ArrayList<>();
        int groupSize = 500;
        for (int j = 0; j < kMeansCluster.size(); j += groupSize) {
            int end = Math.min(j + groupSize, kMeansCluster.size());
            partition.add(new ArrayList<>(kMeansCluster.subList(j, end)));
        }
        log.info("Completing parting. {}", partition.size());
        List<double[]> vectorRes = new ArrayList<>();
        Map<Integer, String> index2Trace = new HashMap<>();
        for (List<Integer> partList : partition) {
            double[][] clusterVectors = new double[partList.size()][];
            Map<Integer, String> clusterIndexTraceIdMap = new HashMap<>();

            for (int j = 0; j < partList.size(); j++) {
                int originalIndex = partList.get(j);
                clusterVectors[j] = vectors[originalIndex];
                clusterIndexTraceIdMap.put(j, indexTraceIdMap.get(originalIndex));
            }

            log.info("Starting performHierarchicalClusteringOfPartition!");
            if (clusterVectors.length == 0) {
                continue;
            }

            if (clusterVectors.length == 1) {
                vectorRes.add(clusterVectors[0]);
                index2Trace.put(vectorRes.size() - 1, clusterIndexTraceIdMap.get(0));
                continue;
            }
            try {
                HierarchicalAgglomerativeClustering hac = new HierarchicalAgglomerativeClustering(clusterVectors);
                List<HierarchicalAgglomerativeClustering.ClusterNode> clusters = hac
                    .fit(HierarchicalAgglomerativeClustering.LinkageMethod.COMPLETE, LOG_VECTORS_CLUSTERING_THRESHOLD);
                log.info("Completing performHierarchicalClusteringOfPartition!");
                for (HierarchicalAgglomerativeClustering.ClusterNode cluster : clusters) {
                    int centroidIndex = hac.getClusterCentroid(cluster);
                    vectorRes.add(clusterVectors[centroidIndex]);
                    index2Trace.put(vectorRes.size() - 1, clusterIndexTraceIdMap.get(centroidIndex));
                }
            } catch (Exception e) {
                log.error("Hierarchical clustering failed: {}", e.getMessage(), e);
                // Fallback: return first point as representative
                vectorRes.add(clusterVectors[0]);
                index2Trace.put(vectorRes.size() - 1, clusterIndexTraceIdMap.get(0));
            }
        }
        return removeSimilarVectors(vectorRes, index2Trace);
    }

    /**
     * Compute the cosine distance pairwise and return the corresponding trace.
     * @param vectorRes List of vectors.
     * @param index2Trace Map of index to their trace id.
     * @return
     */
    private List<String> removeSimilarVectors(List<double[]> vectorRes, Map<Integer, String> index2Trace) {
        Set<Integer> toRemove = new HashSet<>();

        for (int i = 0; i < vectorRes.size(); i++) {
            if (toRemove.contains(i))
                continue;

            for (int j = i + 1; j < vectorRes.size(); j++) {
                if (toRemove.contains(j))
                    continue;

                double distance = calculateCosineSimilarity(vectorRes.get(i), vectorRes.get(j));
                if (distance < LOG_VECTORS_CLUSTERING_THRESHOLD) {
                    toRemove.add(j);
                }
            }
        }
        List<String> result = new ArrayList<>();
        for (int i = 0; i < vectorRes.size(); i++) {
            if (!toRemove.contains(i)) {
                result.add(index2Trace.get(i));
            }
        }
        return result;
    }

    public static class Factory implements Tool.Factory<LogPatternAnalysisTool> {
        private Client client;

        private static LogPatternAnalysisTool.Factory INSTANCE;

        /**
         * Create or return the singleton factory instance
         */
        public static LogPatternAnalysisTool.Factory getInstance() {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            synchronized (LogPatternAnalysisTool.class) {
                if (INSTANCE != null) {
                    return INSTANCE;
                }
                INSTANCE = new LogPatternAnalysisTool.Factory();
                return INSTANCE;
            }
        }

        /**
         * Initialize this factory
         *
         * @param client The OpenSearch client
         */
        public void init(Client client) {
            this.client = client;
        }

        @Override
        public LogPatternAnalysisTool create(Map<String, Object> map) {

            return new LogPatternAnalysisTool(client);
        }

        @Override
        public String getDefaultDescription() {
            return DEFAULT_DESCRIPTION;
        }

        @Override
        public String getDefaultType() {
            return TYPE;
        }

        @Override
        public String getDefaultVersion() {
            return null;
        }
    }
}
