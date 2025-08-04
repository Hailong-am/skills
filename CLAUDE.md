# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenSearch Skills is a plugin that provides tools for the OpenSearch ml-commons agent framework. It contains various search and analysis tools that can be used by AI agents to interact with OpenSearch data.

## Architecture

The codebase is organized as:
- **Tools**: Main functionality lives in `src/main/java/org/opensearch/agent/tools/` - each tool implements the `Tool` interface from ml-common
- **REST**: HTTP endpoints in `src/main/java/org/opensearch/rest/` for dynamic tool execution
- **Plugin**: Main plugin entry point in `ToolPlugin.java` that registers all tools with the ML framework

## Key Tools Available

- **LogPatternTool**: Analyzes log patterns and anomalies
- **LogPatternAnalysisTool**: Advanced log pattern analysis
- **NeuralSparseSearchTool**: Neural search capabilities
- **VectorDBTool**: Vector database operations
- **RAGTool**: Retrieval-augmented generation
- **PPLTool**: Piped Processing Language execution
- **WebSearchTool**: Web crawling and search
- **Alert/Anomaly Detection Tools**: CreateAlertTool, SearchAlertsTool, CreateAnomalyDetectorTool, etc.

## Build Commands

```bash
# Clean build
./gradlew clean

# Build and test
./gradlew build

# Build and publish to local Maven
./gradlew publishToMavenLocal

# Run integration tests
./gradlew integTest

# Run single test class
./gradlew test --tests "org.opensearch.agent.tools.LogPatternToolTests"

# Run with security enabled
./gradlew integTest -Dsecurity.enabled=true

# Run with remote cluster
./gradlew integTestRemote -Dtests.rest.cluster=localhost:9200 -Dhttps=true -Duser=admin -Dpassword=admin
```

## Development Setup

1. **Prerequisites**: JDK 11+ (JAVA_HOME must point to JDK 11+)
2. **IDE**: Import `settings.gradle` in IntelliJ IDEA
3. **Dependencies**: Uses OpenSearch plugin ecosystem (ml-common, sql-plugin, anomaly-detection, etc.)

## Adding New Tools

1. Create new tool class in `src/main/java/org/opensearch/agent/tools/`
2. Implement `Tool` interface from ml-common
3. Add factory initialization in `ToolPlugin.java:createComponents()`
4. Register tool factory in `ToolPlugin.getToolFactories()`
5. Add corresponding test in `src/test/java/org/opensearch/agent/tools/`

## Testing

- Unit tests: `src/test/java/` (use JUnit 4/5)
- Integration tests: `src/test/java/org/opensearch/integTest/` (use RestIntegTestTask)
- All tests run with `./gradlew test`
- Integration tests require running OpenSearch cluster