/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.agent.job;

import static org.opensearch.agent.indices.SkillsIndexEnum.SKILLS_INDEX_SUMMARY;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.agent.indices.IndicesHelper;
import org.opensearch.client.Client;
import org.opensearch.client.Requests;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexTemplateMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.regex.Regex;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.index.Index;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.ml.common.output.model.ModelTensorOutput;
import org.opensearch.ml.common.output.model.ModelTensors;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;

import com.google.common.hash.Hashing;

import lombok.Builder;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;

/**
 * Take index mapping and sample data as summary, embedding it and save to k-NN index as vector store
 */
@Log4j2
public class IndexSummaryEmbeddingJob implements Runnable {

    private Client client;
    private ClusterService clusterService;
    private IndicesHelper indicesHelper;
    private MLClients mlClients;

    public static String INDEX_SUMMARY_EMBEDDING_INDEX = SKILLS_INDEX_SUMMARY.getIndexName();
    public static String INDEX_SUMMARY_EMBEDDING_FIELD_PREFIX = "index_summary_embedding";
    public static String INDEX_NAME_FIELD = "index_name";
    public static String DATA_STREAM_FIELD = "data_stream";
    public static String INDEX_PATTERNS_FIELD = "index_patterns";
    public static String ALIAS_FIELD = "alias";
    public static String INDEX_SUMMARY_FIELD = "index_summary";

    public static String INDEX_NAME = "index";
    public static String DATA_STREAM = "data_stream";
    public static String ALIASES = "aliases";
    public static String INDEX_PATTERNS = "index_patterns";
    public static String INDEX_SUMMARY = "summary";
    public static String INDEX_EMBEDDING = "embedding";
    public static String SENTENCE_EMBEDDING = "sentence_embedding";
    public static int DEFAULT_TIMEOUT_SECOND = 30;
    public static int TOKEN_LIMIT = 8192;

    @Setter
    private List<String> adhocIndexName;

    @Setter
    private List<String> adhocModelIds;

    @Builder
    public IndexSummaryEmbeddingJob(Client client, ClusterService clusterService, IndicesHelper indicesHelper, MLClients mlClients) {
        this.client = client;
        this.clusterService = clusterService;
        this.indicesHelper = indicesHelper;
        this.mlClients = mlClients;
    }

    @Override
    public void run() {
        // TODO to distribute to other nodes to execute the workload other than cluster manager node
        // search agent with IndexRoutingTool
        mlClients.getModelIdsForIndexRoutingTool(adhocModelIds, ActionListener.wrap(embeddingModelIds -> {
            // no embedding model
            if (embeddingModelIds.isEmpty()) {
                return;
            }

            // mapping and simple data
            List<Map<String, Object>> indexMetaAndSamples = getAllIndexMappingAndSampleData();

            // no index at all
            if (indexMetaAndSamples.isEmpty()) {
                return;
            }

            for (String modelId : embeddingModelIds) {
                List<String> embeddingDocs = indexMetaAndSamples
                    .stream()
                    .map(sample -> (String) sample.get(INDEX_SUMMARY))
                    .collect(Collectors.toList());

                List<ModelTensors> mlModelOutputs = mlClients.getEmbeddingResult(modelId, embeddingDocs, true, mlTaskResponse -> {
                    ModelTensorOutput output = (ModelTensorOutput) mlTaskResponse.getOutput();
                    return output.getMlModelOutputs();
                });

                for (int i = 0; i < mlModelOutputs.size(); i++) {
                    Number[] vector = mlModelOutputs.get(i).getMlModelTensors().get(0).getData();
                    indexMetaAndSamples.get(i).put(INDEX_EMBEDDING, vector);
                }

                // write to k-NN index
                indexSummaryVector(INDEX_SUMMARY_EMBEDDING_INDEX, indexMetaAndSamples, modelId);
            }

            AgentMonitorJob.setProcessedModelIds(embeddingModelIds, adhocModelIds == null);
        }, e -> log.error("Search agent error happened", e)));
    }

    private List<Map<String, Object>> getAllIndexMappingAndSampleData() {
        Metadata metadata = clusterService.state().metadata();
        Map<String, IndexMetadata> indices = metadata.indices();

        if (Objects.nonNull(this.adhocIndexName) && !adhocIndexName.isEmpty()) {
            Map<String, IndexMetadata> adhocIndices = new HashMap<>();
            for (String index : adhocIndexName) {
                adhocIndices.put(index, indices.get(index));
            }
            indices = adhocIndices;
        }
        // data streams
        Map<String, DataStream> dataStreamMap = metadata.dataStreams();
        Map<String, String> indexDataStreamLookup = new HashMap<>();
        dataStreamMap.values().forEach(dataStream -> {
            String dsName = dataStream.getName();
            dataStream.getIndices().stream().map(Index::getName).forEach(it -> indexDataStreamLookup.put(it, dsName));
        });

        // index patterns from index template
        List<String> patterns = new ArrayList<>();
        for (final IndexTemplateMetadata template : metadata.templates().values()) {
            patterns.addAll(template.patterns());
        }
        for (ComposableIndexTemplate composableIndexTemplate : metadata.templatesV2().values()) {
            patterns.addAll(composableIndexTemplate.indexPatterns());
        }

        List<Map<String, Object>> indexSummaryList = new ArrayList<>();

        for (Map.Entry<String, IndexMetadata> indexEntry : indices.entrySet()) {
            Map<String, Object> indexSummaryMap = new HashMap<>();
            String indexName = indexEntry.getKey();
            IndexMetadata indexMetadata = indexEntry.getValue();

            indexSummaryMap.put(INDEX_NAME, indexName);

            // ignore system index or index name start with dot
            if (indexMetadata.isSystem() || (indexName.startsWith(".") && !indexDataStreamLookup.containsKey(indexName))) {
                log.debug("Skip system index {}", indexName);
                continue;
            }
            indexSummaryMap.put(DATA_STREAM, indexDataStreamLookup.get(indexName));

            List<String> indexPatterns = patterns
                .stream()
                .filter(pattern -> Regex.simpleMatch(pattern, indexName))
                .collect(Collectors.toList());
            indexSummaryMap.put(INDEX_PATTERNS, indexPatterns);
            indexSummaryMap.put(ALIASES, indexMetadata.getAliases().keySet());

            // if index have no mapping at all
            if (indexMetadata.mapping() == null) {
                log.debug("No mapping for index {}", indexName);
                continue;
            }
            Map<String, Object> sourceAsMap = indexMetadata.mapping().getSourceAsMap();
            try (XContentBuilder builder = MediaTypeRegistry.contentBuilder(MediaTypeRegistry.JSON)) {
                builder.map(sourceAsMap);
                String mapping = builder.toString();

                // sample data
                SearchRequest indexSearchRequest = Requests.searchRequest(indexName);
                SearchSourceBuilder sourceBuilder = new SearchSourceBuilder().query(new MatchAllQueryBuilder()).size(5);
                indexSearchRequest.source(sourceBuilder);

                ActionFuture<SearchResponse> searchFuture = client.search(indexSearchRequest);
                SearchResponse searchResponse = searchFuture.get(DEFAULT_TIMEOUT_SECOND, TimeUnit.SECONDS);

                List<String> documents = new ArrayList<>();
                int tokenNumber = 0;
                for (SearchHit hit : searchResponse.getHits()) {
                    String docContent = Strings.toString(MediaTypeRegistry.JSON, hit);
                    int tokens = countToken(docContent);
                    if (tokenNumber + tokens > TOKEN_LIMIT) {
                        // at least 1 sample data
                        if (documents.isEmpty()) {
                            documents.add(docContent);
                        }
                        break;
                    }
                    documents.add(docContent);
                    tokenNumber += tokens;
                }

                String indexSummary = String.format(Locale.ROOT, "Index Mappings:%s\\nSample data:\\n%s", mapping, documents);

                indexSummaryMap.put(INDEX_SUMMARY, indexSummary);

            } catch (Exception e) {
                log.error("Get index mapping and sample data failed for index {}", indexName, e);
            }

            indexSummaryList.add(indexSummaryMap);
        }

        return indexSummaryList;
    }

    /**
     * 1 token ~= 4 chars in English
     * 1 token ~= ¾ words
     * 100 tokens ~= 75 words
     * @param sentence
     * @return
     */
    private int countToken(String sentence) {
        if (sentence == null) {
            return 0;
        }
        return sentence.getBytes(StandardCharsets.UTF_8).length / 4;
    }

    private void indexSummaryVector(String writeIndex, List<Map<String, Object>> docs, String modelId) {
        // init index and mapping
        indicesHelper.initIndexSummaryEmbeddingIndex(ActionListener.wrap(initialed -> {
            if (initialed) {
                BulkUpdateVectorField(writeIndex, docs, modelId);
            }
        }, e -> {
            if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                BulkUpdateVectorField(writeIndex, docs, modelId);
            } else {
                log.error("Failed to create index for index summary embedding", e);
            }
        }));
    }

    private void BulkUpdateVectorField(String writeIndex, List<Map<String, Object>> docs, String modelId) {
        indicesHelper.addNewVectorField(SKILLS_INDEX_SUMMARY.getIndexName(), modelId, ActionListener.wrap(r -> {
            if (r) {
                bulkWrite(writeIndex, docs, modelId);
            } else {
                log.error("Add vector field for model {} failed", modelId);
            }
        }, ex -> log.error("Add vector field for model {} failed", modelId, ex)));
    }

    private void bulkWrite(String writeIndex, List<Map<String, Object>> docs, String modelId) {
        BulkRequest bulkRequest = Requests.bulkRequest();
        for (Map<String, Object> doc : docs) {
            Number[] embedding = (Number[]) doc.get(INDEX_EMBEDDING);

            Map<String, Object> docMap = new HashMap<>();
            String indexName = (String) doc.get(INDEX_NAME);
            docMap.put(INDEX_NAME_FIELD, indexName);
            docMap.put(INDEX_PATTERNS_FIELD, doc.get(INDEX_PATTERNS));
            docMap.put(DATA_STREAM_FIELD, doc.get(DATA_STREAM));
            docMap.put(ALIASES, doc.get(ALIAS_FIELD));
            docMap.put(INDEX_SUMMARY_FIELD, doc.get(INDEX_SUMMARY));
            docMap.put(INDEX_SUMMARY_EMBEDDING_FIELD_PREFIX + "_" + modelId, embedding);

            String docId = Hashing.sha256().hashString(indexName, StandardCharsets.UTF_8).toString();

            bulkRequest.add(new UpdateRequest(writeIndex, docId).doc(docMap, MediaTypeRegistry.JSON).docAsUpsert(true));
        }
        client.bulk(bulkRequest, ActionListener.wrap(r -> {
            if (r.hasFailures()) {
                log.error("Bulk create index summary embedding with failure {}", r.buildFailureMessage());
            } else {
                log.debug("Bulk create index summary embedding finished with {}", r.getTook());
            }
        }, exception -> log.error("Bulk create index summary embedding failed", exception)));
    }

    public void bulkDelete(String writeIndex, List<String> indexNames) {
        BulkRequest bulkRequest = Requests.bulkRequest();
        for (String indexName : indexNames) {
            String docId = String.valueOf(indexName.hashCode());
            bulkRequest.add(new DeleteRequest(writeIndex, docId));
        }
        client.bulk(bulkRequest, ActionListener.wrap(r -> {
            if (r.hasFailures()) {
                log.error("Bulk delete index summary embedding with failure {}", r.buildFailureMessage());
            } else {
                log.debug("Bulk delete index summary embedding finished with {}", r.getTook());
            }
        }, exception -> log.error("Bulk delete index summary embedding failed", exception)));
    }
}
