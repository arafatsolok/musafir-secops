package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type SearchService struct {
	client *elasticsearch.Client
	ctx    context.Context
}

type SearchQuery struct {
	Query        string                 `json:"query"`
	Filters      map[string]interface{} `json:"filters"`
	Sort         []map[string]string    `json:"sort"`
	From         int                    `json:"from"`
	Size         int                    `json:"size"`
	Aggregations map[string]interface{} `json:"aggregations"`
}

type SearchResult struct {
	Hits         []SearchHit            `json:"hits"`
	Total        int64                  `json:"total"`
	MaxScore     float64                `json:"max_score"`
	Aggregations map[string]interface{} `json:"aggregations"`
	Took         int64                  `json:"took"`
}

type SearchHit struct {
	ID     string                 `json:"_id"`
	Score  float64                `json:"_score"`
	Source map[string]interface{} `json:"_source"`
}

type Document struct {
	ID        string                 `json:"id"`
	Index     string                 `json:"index"`
	Type      string                 `json:"type"`
	Content   map[string]interface{} `json:"content"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type SearchIndex struct {
	Name          string                 `json:"name"`
	Mappings      map[string]interface{} `json:"mappings"`
	Settings      map[string]interface{} `json:"settings"`
	Aliases       []string               `json:"aliases"`
	CreatedAt     time.Time              `json:"created_at"`
	DocumentCount int64                  `json:"document_count"`
}

type SearchSuggestion struct {
	Text    string  `json:"text"`
	Score   float64 `json:"score"`
	Context string  `json:"context"`
}

type SearchAnalytics struct {
	QueryCount   int64            `json:"query_count"`
	AvgQueryTime float64          `json:"avg_query_time"`
	TopQueries   []string         `json:"top_queries"`
	SearchVolume map[string]int64 `json:"search_volume"`
	ErrorRate    float64          `json:"error_rate"`
	LastUpdated  time.Time        `json:"last_updated"`
}

func NewSearchService() *SearchService {
	esURL := os.Getenv("ELASTICSEARCH_URL")
	if esURL == "" {
		esURL = "http://localhost:9200"
	}

	cfg := elasticsearch.Config{
		Addresses: []string{esURL},
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating Elasticsearch client: %v", err)
	}

	ctx := context.Background()

	// Test connection
	res, err := client.Info()
	if err != nil {
		log.Fatalf("Error getting Elasticsearch info: %v", err)
	}
	defer res.Body.Close()

	return &SearchService{
		client: client,
		ctx:    ctx,
	}
}

func (s *SearchService) Initialize() {
	// Create default indices
	s.createDefaultIndices()

	// Start index management
	go s.manageIndices()

	log.Println("Search service initialized successfully")
}

func (s *SearchService) createDefaultIndices() {
	indices := []string{
		"musafir_events",
		"musafir_alerts",
		"musafir_threats",
		"musafir_logs",
		"musafir_metrics",
		"musafir_traces",
		"musafir_users",
		"musafir_assets",
	}

	for _, index := range indices {
		s.createIndex(index)
	}
}

func (s *SearchService) createIndex(indexName string) {
	// Check if index exists
	exists, err := s.client.Indices.Exists([]string{indexName})
	if err != nil {
		log.Printf("Error checking if index exists: %v", err)
		return
	}
	defer exists.Body.Close()

	if exists.StatusCode == 200 {
		return // Index already exists
	}

	// Create index with mapping
	mapping := s.getIndexMapping(indexName)

	req := esapi.IndicesCreateRequest{
		Index: indexName,
		Body:  strings.NewReader(mapping),
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		log.Printf("Error creating index %s: %v", indexName, err)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("Error creating index %s: %s", indexName, res.String())
		return
	}

	log.Printf("Created index: %s", indexName)
}

func (s *SearchService) getIndexMapping(indexName string) string {
	baseMapping := `{
		"mappings": {
			"properties": {
				"timestamp": {
					"type": "date"
				},
				"service": {
					"type": "keyword"
				},
				"level": {
					"type": "keyword"
				},
				"message": {
					"type": "text",
					"analyzer": "standard"
				},
				"tags": {
					"type": "keyword"
				},
				"metadata": {
					"type": "object"
				}
			}
		},
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0,
			"analysis": {
				"analyzer": {
					"custom_analyzer": {
						"type": "custom",
						"tokenizer": "standard",
						"filter": ["lowercase", "stop", "snowball"]
					}
				}
			}
		}
	}`

	// Customize mapping based on index type
	switch indexName {
	case "musafir_events":
		return `{
			"mappings": {
				"properties": {
					"timestamp": {"type": "date"},
					"event_type": {"type": "keyword"},
					"severity": {"type": "keyword"},
					"source_ip": {"type": "ip"},
					"destination_ip": {"type": "ip"},
					"user_id": {"type": "keyword"},
					"asset_id": {"type": "keyword"},
					"process_name": {"type": "keyword"},
					"command": {"type": "text"},
					"file_path": {"type": "keyword"},
					"entropy": {"type": "float"},
					"risk_score": {"type": "float"},
					"metadata": {"type": "object"}
				}
			}
		}`
	case "musafir_alerts":
		return `{
			"mappings": {
				"properties": {
					"timestamp": {"type": "date"},
					"alert_type": {"type": "keyword"},
					"severity": {"type": "keyword"},
					"status": {"type": "keyword"},
					"title": {"type": "text"},
					"description": {"type": "text"},
					"source": {"type": "keyword"},
					"target": {"type": "keyword"},
					"confidence": {"type": "float"},
					"risk_score": {"type": "float"},
					"tags": {"type": "keyword"},
					"metadata": {"type": "object"}
				}
			}
		}`
	case "musafir_threats":
		return `{
			"mappings": {
				"properties": {
					"timestamp": {"type": "date"},
					"threat_type": {"type": "keyword"},
					"severity": {"type": "keyword"},
					"status": {"type": "keyword"},
					"title": {"type": "text"},
					"description": {"type": "text"},
					"source_ip": {"type": "ip"},
					"target_ip": {"type": "ip"},
					"user_id": {"type": "keyword"},
					"asset_id": {"type": "keyword"},
					"confidence": {"type": "float"},
					"risk_score": {"type": "float"},
					"iocs": {"type": "keyword"},
					"attack_vector": {"type": "keyword"},
					"metadata": {"type": "object"}
				}
			}
		}`
	}

	return baseMapping
}

func (s *SearchService) IndexDocument(doc Document) error {
	docJSON, err := json.Marshal(doc.Content)
	if err != nil {
		return err
	}

	req := esapi.IndexRequest{
		Index:      doc.Index,
		DocumentID: doc.ID,
		Body:       strings.NewReader(string(docJSON)),
		Refresh:    "true",
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing document: %s", res.String())
	}

	return nil
}

func (s *SearchService) Search(index string, query SearchQuery) (*SearchResult, error) {
	searchBody := s.buildSearchBody(query)

	req := esapi.SearchRequest{
		Index: []string{index},
		Body:  strings.NewReader(searchBody),
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("error searching: %s", res.String())
	}

	var searchResponse map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&searchResponse); err != nil {
		return nil, err
	}

	return s.parseSearchResponse(searchResponse), nil
}

func (s *SearchService) buildSearchBody(query SearchQuery) string {
	searchBody := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"multi_match": map[string]interface{}{
							"query":  query.Query,
							"fields": []string{"title^2", "description", "message", "content"},
						},
					},
				},
			},
		},
		"from": query.From,
		"size": query.Size,
	}

	// Add filters
	if len(query.Filters) > 0 {
		filters := []map[string]interface{}{}
		for field, value := range query.Filters {
			filters = append(filters, map[string]interface{}{
				"term": map[string]interface{}{
					field: value,
				},
			})
		}
		searchBody["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = filters
	}

	// Add sorting
	if len(query.Sort) > 0 {
		searchBody["sort"] = query.Sort
	}

	// Add aggregations
	if len(query.Aggregations) > 0 {
		searchBody["aggs"] = query.Aggregations
	}

	searchBodyJSON, _ := json.Marshal(searchBody)
	return string(searchBodyJSON)
}

func (s *SearchService) parseSearchResponse(response map[string]interface{}) *SearchResult {
	hits := response["hits"].(map[string]interface{})

	var searchHits []SearchHit
	for _, hit := range hits["hits"].([]interface{}) {
		hitMap := hit.(map[string]interface{})
		searchHit := SearchHit{
			ID:     hitMap["_id"].(string),
			Score:  hitMap["_score"].(float64),
			Source: hitMap["_source"].(map[string]interface{}),
		}
		searchHits = append(searchHits, searchHit)
	}

	result := &SearchResult{
		Hits:     searchHits,
		Total:    int64(hits["total"].(map[string]interface{})["value"].(float64)),
		MaxScore: hits["max_score"].(float64),
		Took:     int64(response["took"].(float64)),
	}

	// Add aggregations if present
	if aggs, exists := response["aggregations"]; exists {
		result.Aggregations = aggs.(map[string]interface{})
	}

	return result
}

func (s *SearchService) GetSuggestions(index, query string, size int) ([]SearchSuggestion, error) {
	suggestBody := map[string]interface{}{
		"suggest": map[string]interface{}{
			"text": query,
			"completion": map[string]interface{}{
				"field": "suggest",
				"size":  size,
			},
		},
	}

	bodyJSON, _ := json.Marshal(suggestBody)

	req := esapi.SearchRequest{
		Index: []string{index},
		Body:  strings.NewReader(string(bodyJSON)),
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("error getting suggestions: %s", res.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	return s.parseSuggestions(response), nil
}

func (s *SearchService) parseSuggestions(response map[string]interface{}) []SearchSuggestion {
	var suggestions []SearchSuggestion

	if suggest, exists := response["suggest"]; exists {
		suggestMap := suggest.(map[string]interface{})
		if completion, exists := suggestMap["completion"]; exists {
			completionArray := completion.([]interface{})
			for _, item := range completionArray {
				itemMap := item.(map[string]interface{})
				if options, exists := itemMap["options"]; exists {
					for _, option := range options.([]interface{}) {
						optionMap := option.(map[string]interface{})
						suggestion := SearchSuggestion{
							Text:  optionMap["text"].(string),
							Score: optionMap["_score"].(float64),
						}
						suggestions = append(suggestions, suggestion)
					}
				}
			}
		}
	}

	return suggestions
}

func (s *SearchService) GetAnalytics() (*SearchAnalytics, error) {
	// Query search analytics from Elasticsearch
	query := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"query_count": map[string]interface{}{
				"value_count": map[string]interface{}{
					"field": "query",
				},
			},
			"avg_query_time": map[string]interface{}{
				"avg": map[string]interface{}{
					"field": "query_time",
				},
			},
			"top_queries": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "query",
					"size":  10,
				},
			},
		},
	}

	queryJSON, _ := json.Marshal(query)

	req := esapi.SearchRequest{
		Index: []string{"musafir_search_logs"},
		Body:  strings.NewReader(string(queryJSON)),
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("error getting analytics: %s", res.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	return s.parseAnalytics(response), nil
}

func (s *SearchService) parseAnalytics(response map[string]interface{}) *SearchAnalytics {
	analytics := &SearchAnalytics{
		LastUpdated: time.Now(),
	}

	if aggs, exists := response["aggregations"]; exists {
		aggsMap := aggs.(map[string]interface{})

		if queryCount, exists := aggsMap["query_count"]; exists {
			analytics.QueryCount = int64(queryCount.(map[string]interface{})["value"].(float64))
		}

		if avgQueryTime, exists := aggsMap["avg_query_time"]; exists {
			analytics.AvgQueryTime = avgQueryTime.(map[string]interface{})["value"].(float64)
		}

		if topQueries, exists := aggsMap["top_queries"]; exists {
			buckets := topQueries.(map[string]interface{})["buckets"].([]interface{})
			for _, bucket := range buckets {
				bucketMap := bucket.(map[string]interface{})
				analytics.TopQueries = append(analytics.TopQueries, bucketMap["key"].(string))
			}
		}
	}

	return analytics
}

func (s *SearchService) DeleteDocument(index, id string) error {
	req := esapi.DeleteRequest{
		Index:      index,
		DocumentID: id,
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error deleting document: %s", res.String())
	}

	return nil
}

func (s *SearchService) UpdateDocument(index, id string, doc map[string]interface{}) error {
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	req := esapi.UpdateRequest{
		Index:      index,
		DocumentID: id,
		Body:       strings.NewReader(fmt.Sprintf(`{"doc": %s}`, string(docJSON))),
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error updating document: %s", res.String())
	}

	return nil
}

func (s *SearchService) manageIndices() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupOldIndices()
			s.optimizeIndices()
		}
	}
}

func (s *SearchService) cleanupOldIndices() {
	// Delete indices older than 30 days
	cutoffDate := time.Now().AddDate(0, 0, -30)

	req := esapi.IndicesDeleteRequest{
		Index: []string{fmt.Sprintf("musafir_*_%s", cutoffDate.Format("2006.01.02"))},
	}

	res, err := req.Do(s.ctx, s.client)
	if err != nil {
		log.Printf("Error cleaning up old indices: %v", err)
		return
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Printf("Error cleaning up old indices: %s", res.String())
	}
}

func (s *SearchService) optimizeIndices() {
	// Optimize indices for better performance
	indices := []string{
		"musafir_events",
		"musafir_alerts",
		"musafir_threats",
		"musafir_logs",
	}

	for _, index := range indices {
		req := esapi.IndicesOptimizeRequest{
			Index: []string{index},
		}

		res, err := req.Do(s.ctx, s.client)
		if err != nil {
			log.Printf("Error optimizing index %s: %v", index, err)
			continue
		}
		defer res.Body.Close()

		if res.IsError() {
			log.Printf("Error optimizing index %s: %s", index, res.String())
		}
	}
}

func (s *SearchService) Close() {
	// Elasticsearch client doesn't need explicit closing
}

func main() {
	searchService := NewSearchService()
	searchService.Initialize()

	// Keep service running
	select {}
}
