/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.integTest;

import static org.hamcrest.Matchers.containsString;
import static org.opensearch.ml.common.utils.StringUtils.gson;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import org.hamcrest.MatcherAssert;
import org.junit.After;
import org.junit.Before;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import lombok.SneakyThrows;

public class LogPatternAnalysisToolIT extends BaseAgentToolsIT {

    public static String requestBodyResourceFile =
        "org/opensearch/agent/tools/register_flow_agent_of_log_pattern_analysis_tool_request_body.json";
    public String registerAgentRequestBody;
    public static String TEST_LOG_INDEX_NAME = "test_log_analysis_index";

    private String agentId;

    @Before
    @SneakyThrows
    public void setUp() {
        super.setUp();
        prepareLogIndex();
        registerAgentRequestBody = Files.readString(Path.of(this.getClass().getClassLoader().getResource(requestBodyResourceFile).toURI()));
        agentId = createAgent(registerAgentRequestBody);
    }

    @After
    @SneakyThrows
    public void tearDown() {
        super.tearDown();
        deleteExternalIndices();
    }

    @SneakyThrows
    private void prepareLogIndex() {
        createIndexWithConfiguration(
            TEST_LOG_INDEX_NAME,
            "{\n"
                + "  \"mappings\": {\n"
                + "    \"properties\": {\n"
                + "      \"@timestamp\": {\n"
                + "        \"type\": \"date\",\n"
                + "        \"format\": \"yyyy-MM-dd HH:mm:ss||strict_date_optional_time||epoch_millis\"\n"
                + "      },\n"
                + "      \"message\": {\n"
                + "        \"type\": \"text\"\n"
                + "      },\n"
                + "      \"traceId\": {\n"
                + "        \"type\": \"keyword\"\n"
                + "      },\n"
                + "      \"serviceName\": {\n"
                + "        \"type\": \"keyword\"\n"
                + "      }\n"
                + "    }\n"
                + "  }\n"
                + "}"
        );

        // Add baseline data in base time range (09:00:00 to 10:00:00)
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "base1",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 09:30:00", "System startup completed", "trace-base-001", "auth-service")
        );
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "base2",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 09:45:00", "Database connection established", "trace-base-002", "db-service")
        );
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "base3",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 09:50:00", "User session initialized", "trace-base-003", "auth-service")
        );

        // Add test log data with error keywords for logInsight
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "1",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 10:00:00", "User login successful", "trace-001", "auth-service")
        );
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "2",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 10:01:00", "Database connection established", "trace-001", "db-service")
        );
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "3",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 10:02:00", "Error connection timeout failed", "trace-002", "db-service")
        );
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "4",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 10:03:00", "User logout completed", "trace-001", "auth-service")
        );
        addDocToIndex(
            TEST_LOG_INDEX_NAME,
            "5",
            List.of("@timestamp", "message", "traceId", "serviceName"),
            List.of("2025-01-01 10:04:00", "Exception in authentication service", "trace-003", "auth-service")
        );
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolLogInsight() {
        // Test data in selection range 10:00-10:05 with error keywords:
        //   doc "3": 10:02:00 "Error connection timeout failed" (db-service)
        //   doc "5": 10:04:00 "Exception in authentication service" (auth-service)
        String result = executeAgent(
            agentId,
            String
                .format(
                    Locale.ROOT,
                    "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\"}}",
                    TEST_LOG_INDEX_NAME
                )
        );
        assertNotNull(result);
        JsonObject json = gson.fromJson(result, JsonObject.class);

        // Verify logInsights: 2 error docs should produce patterns with total count = 2
        JsonArray logInsights = json.getAsJsonArray("logInsights");
        assertNotNull(logInsights);
        assertFalse("Expected at least one error pattern", logInsights.isEmpty());
        double insightsTotalCount = 0;
        for (int i = 0; i < logInsights.size(); i++) {
            JsonObject insight = logInsights.get(i).getAsJsonObject();
            assertFalse("Pattern should not be empty", insight.get("pattern").getAsString().isEmpty());
            assertTrue("Each pattern count should be > 0", insight.get("count").getAsDouble() > 0);
            assertNotNull("Sample logs should be present", insight.getAsJsonArray("sampleLogs"));
            assertFalse("Sample logs should not be empty", insight.getAsJsonArray("sampleLogs").isEmpty());
            insightsTotalCount += insight.get("count").getAsDouble();
        }
        assertEquals("Total logInsights count should match 2 error docs", 2.0, insightsTotalCount, 0.01);

        // Verify histogram: same 2 error docs bucketed by time
        JsonArray histogram = json.getAsJsonArray("histogram");
        assertNotNull(histogram);
        assertFalse("Expected at least one histogram bucket", histogram.isEmpty());
        double histogramTotalCount = 0;
        for (int i = 0; i < histogram.size(); i++) {
            JsonObject bucket = histogram.get(i).getAsJsonObject();
            assertFalse("Bucket timeBucket should not be empty", bucket.get("timeBucket").getAsString().isEmpty());
            assertFalse("Bucket pattern should not be empty", bucket.get("pattern").getAsString().isEmpty());
            assertTrue("Bucket count should be > 0", bucket.get("count").getAsDouble() > 0);
            histogramTotalCount += bucket.get("count").getAsDouble();
        }
        assertEquals("Total histogram count should match 2 error docs", 2.0, histogramTotalCount, 0.01);

        // 5min range → ceil(5/20) = 1m
        assertEquals("1m", json.get("histogramInterval").getAsString());
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolWithBaseTimeRange() {
        String result = executeAgent(
            agentId,
            String
                .format(
                    Locale.ROOT,
                    "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"baseTimeRangeStart\": \"2025-01-01 09:00:00\", \"baseTimeRangeEnd\": \"2025-01-01 10:00:00\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\"}}",
                    TEST_LOG_INDEX_NAME
                )
        );
        assertNotNull(result);
        assertTrue(result.contains("patternMapDifference"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolWithTraceField() {
        String result = executeAgent(
            agentId,
            String
                .format(
                    Locale.ROOT,
                    "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"traceFieldName\": \"traceId\", \"baseTimeRangeStart\": \"2025-01-01 09:00:00\", \"baseTimeRangeEnd\": \"2025-01-01 10:00:00\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\"}}",
                    TEST_LOG_INDEX_NAME
                )
        );
        System.out.println(result);
        assertNotNull(result);
        assertTrue(result.contains("BASE") || result.contains("EXCEPTIONAL"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolMissingRequiredParameters() {
        Exception exception = assertThrows(Exception.class, () -> executeAgent(agentId, "{\"parameters\": {\"index\": \"%s\"}}"));
        MatcherAssert.assertThat(exception.getMessage(), containsString("Missing required parameters"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolInvalidIndex() {
        Exception exception = assertThrows(
            Exception.class,
            () -> executeAgent(
                agentId,
                "{\"parameters\": {\"index\": \"non_existent_index\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\"}}"
            )
        );
        MatcherAssert.assertThat(exception.getMessage(), containsString("no such index"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolNonExistentLogField() {
        Exception exception = assertThrows(
            Exception.class,
            () -> executeAgent(
                agentId,
                "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"nonexistent_field\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\"}}"
            )
        );
        MatcherAssert.assertThat(exception.getMessage(), containsString("not a valid term"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolInvalidTimeFormat() {
        Exception exception = assertThrows(
            Exception.class,
            () -> executeAgent(
                agentId,
                "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"selectionTimeRangeStart\": \"invalid-time-format\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\"}}"
            )
        );
        MatcherAssert.assertThat(exception.getMessage(), containsString("not a valid term"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolLogInsightWithFilter() {
        // With filter serviceName='db-service', only 1 error doc matches:
        //   doc "3": 10:02:00 "Error connection timeout failed" (db-service)
        String result = executeAgent(
            agentId,
            """
                {"parameters": {"index": "%s", "timeField": "@timestamp", "logFieldName": "message", \
                "selectionTimeRangeStart": "2025-01-01 10:00:00", "selectionTimeRangeEnd": "2025-01-01 10:05:00", \
                "filter": "serviceName='db-service'"}}"""
                .formatted(TEST_LOG_INDEX_NAME)
        );
        assertNotNull(result);
        JsonObject json = gson.fromJson(result, JsonObject.class);

        // Verify logInsights: only 1 error doc from db-service
        JsonArray logInsights = json.getAsJsonArray("logInsights");
        assertNotNull(logInsights);
        assertFalse("Expected at least one error pattern from db-service", logInsights.isEmpty());
        double insightsTotalCount = 0;
        for (int i = 0; i < logInsights.size(); i++) {
            JsonObject insight = logInsights.get(i).getAsJsonObject();
            assertFalse("Pattern should not be empty", insight.get("pattern").getAsString().isEmpty());
            insightsTotalCount += insight.get("count").getAsDouble();
        }
        assertEquals("Total logInsights count should match 1 filtered error doc", 1.0, insightsTotalCount, 0.01);

        // Verify histogram: same 1 error doc bucketed by time
        JsonArray histogram = json.getAsJsonArray("histogram");
        assertNotNull(histogram);
        double histogramTotalCount = 0;
        for (int i = 0; i < histogram.size(); i++) {
            JsonObject bucket = histogram.get(i).getAsJsonObject();
            assertFalse("Bucket timeBucket should not be empty", bucket.get("timeBucket").getAsString().isEmpty());
            assertFalse("Bucket pattern should not be empty", bucket.get("pattern").getAsString().isEmpty());
            histogramTotalCount += bucket.get("count").getAsDouble();
        }
        assertEquals("Total histogram count should match 1 filtered error doc", 1.0, histogramTotalCount, 0.01);

        // 5min range → ceil(5/20) = 1m
        assertEquals("1m", json.get("histogramInterval").getAsString());
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolWithBaseTimeRangeAndFilter() {
        String result = executeAgent(
            agentId,
            String
                .format(
                    Locale.ROOT,
                    "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"baseTimeRangeStart\": \"2025-01-01 09:00:00\", \"baseTimeRangeEnd\": \"2025-01-01 10:00:00\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\", \"filter\": \"serviceName='auth-service'\"}}",
                    TEST_LOG_INDEX_NAME
                )
        );
        assertNotNull(result);
        assertTrue(result.contains("patternMapDifference"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolWithTraceFieldAndFilter() {
        String result = executeAgent(
            agentId,
            String
                .format(
                    Locale.ROOT,
                    "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"traceFieldName\": \"traceId\", \"baseTimeRangeStart\": \"2025-01-01 09:00:00\", \"baseTimeRangeEnd\": \"2025-01-01 10:00:00\", \"selectionTimeRangeStart\": \"2025-01-01 10:00:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:05:00\", \"filter\": \"serviceName='auth-service'\"}}",
                    TEST_LOG_INDEX_NAME
                )
        );
        assertNotNull(result);
        assertTrue(result.contains("BASE") || result.contains("EXCEPTIONAL"));
    }

    @SneakyThrows
    public void testLogPatternAnalysisToolEmptyTimeRange() {
        Exception exception = assertThrows(
            Exception.class,
            () -> executeAgent(
                agentId,
                "{\"parameters\": {\"index\": \"%s\", \"timeField\": \"@timestamp\", \"logFieldName\": \"message\", \"selectionTimeRangeStart\": \"2025-01-01 10:05:00\", \"selectionTimeRangeEnd\": \"2025-01-01 10:00:00\"}}"
            )
        );
        MatcherAssert.assertThat(exception.getMessage(), containsString("not a valid term"));
    }
}
