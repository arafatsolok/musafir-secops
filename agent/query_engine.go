//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// QueryEngine handles threat hunting queries
type QueryEngine struct {
	eventStore    []Envelope
	maxEvents     int
	indexedFields map[string]map[string][]int // field -> value -> event indices
}

// QueryResult represents the result of a query
type QueryResult struct {
	Query        string                 `json:"query"`
	TotalHits    int                    `json:"total_hits"`
	Events       []Envelope             `json:"events"`
	Duration     string                 `json:"duration"`
	Timestamp    string                 `json:"timestamp"`
	Aggregations map[string]interface{} `json:"aggregations,omitempty"`
}

// QueryFilter represents a single filter condition
type QueryFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, contains, regex, gt, lt, in
	Value    interface{} `json:"value"`
}

// NewQueryEngine creates a new query engine
func NewQueryEngine(maxEvents int) *QueryEngine {
	return &QueryEngine{
		eventStore:    make([]Envelope, 0, maxEvents),
		maxEvents:     maxEvents,
		indexedFields: make(map[string]map[string][]int),
	}
}

// AddEvent adds an event to the query engine
func (qe *QueryEngine) AddEvent(event Envelope) {
	// Add to event store
	if len(qe.eventStore) >= qe.maxEvents {
		// Remove oldest event
		qe.eventStore = qe.eventStore[1:]
	}

	eventIndex := len(qe.eventStore)
	qe.eventStore = append(qe.eventStore, event)

	// Index the event
	qe.indexEvent(event, eventIndex)
}

// indexEvent creates indices for fast searching
func (qe *QueryEngine) indexEvent(event Envelope, index int) {
	// Index common fields
	qe.addToIndex("tenant_id", event.TenantID, index)
	qe.addToIndex("event.class", getNestedValue(event.Event, "class"), index)
	qe.addToIndex("event.name", getNestedValue(event.Event, "name"), index)
	// Asset is map[string]string, not map[string]interface{}
	if assetType, ok := event.Asset["type"]; ok {
		qe.addToIndex("asset.type", assetType, index)
	}
	if assetOS, ok := event.Asset["os"]; ok {
		qe.addToIndex("asset.os", assetOS, index)
	}

	// Index event attributes
	if attrs, ok := event.Event["attrs"].(map[string]interface{}); ok {
		for key, value := range attrs {
			fieldName := fmt.Sprintf("attrs.%s", key)
			qe.addToIndex(fieldName, fmt.Sprintf("%v", value), index)
		}
	}
}

// addToIndex adds a value to the field index
func (qe *QueryEngine) addToIndex(field, value string, index int) {
	if qe.indexedFields[field] == nil {
		qe.indexedFields[field] = make(map[string][]int)
	}
	qe.indexedFields[field][value] = append(qe.indexedFields[field][value], index)
}

// ExecuteQuery executes a threat hunting query
func (qe *QueryEngine) ExecuteQuery(query string) *QueryResult {
	startTime := time.Now()

	// Parse the query
	filters, err := qe.parseQuery(query)
	if err != nil {
		log.Printf("Query parse error: %v", err)
		return &QueryResult{
			Query:     query,
			TotalHits: 0,
			Events:    []Envelope{},
			Duration:  time.Since(startTime).String(),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// Execute the query
	matchingEvents := qe.executeFilters(filters)

	// Calculate aggregations
	aggregations := qe.calculateAggregations(matchingEvents)

	return &QueryResult{
		Query:        query,
		TotalHits:    len(matchingEvents),
		Events:       matchingEvents,
		Duration:     time.Since(startTime).String(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Aggregations: aggregations,
	}
}

// parseQuery parses a simple query language
// Supports: field:"value", field:value, field:*pattern*, field>value, field<value
func (qe *QueryEngine) parseQuery(query string) ([]QueryFilter, error) {
	var filters []QueryFilter

	// Simple regex-based parsing
	// Pattern: field:value or field:"value" or field>value etc.
	re := regexp.MustCompile(`(\w+(?:\.\w+)*)\s*([><=:]|\s+(?:AND|OR)\s+)\s*(["\w\*\.\-\:\/]+)`)
	matches := re.FindAllStringSubmatch(query, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			field := match[1]
			operator := strings.TrimSpace(match[2])
			value := strings.Trim(match[3], `"`)

			// Convert operator
			switch operator {
			case ":":
				if strings.Contains(value, "*") {
					filters = append(filters, QueryFilter{
						Field:    field,
						Operator: "contains",
						Value:    strings.ReplaceAll(value, "*", ""),
					})
				} else {
					filters = append(filters, QueryFilter{
						Field:    field,
						Operator: "eq",
						Value:    value,
					})
				}
			case ">":
				filters = append(filters, QueryFilter{
					Field:    field,
					Operator: "gt",
					Value:    value,
				})
			case "<":
				filters = append(filters, QueryFilter{
					Field:    field,
					Operator: "lt",
					Value:    value,
				})
			}
		}
	}

	// If no structured query found, treat as full-text search
	if len(filters) == 0 {
		filters = append(filters, QueryFilter{
			Field:    "_all",
			Operator: "contains",
			Value:    query,
		})
	}

	return filters, nil
}

// executeFilters applies filters to find matching events
func (qe *QueryEngine) executeFilters(filters []QueryFilter) []Envelope {
	var matchingIndices []int

	for i, filter := range filters {
		var currentMatches []int

		if filter.Field == "_all" {
			// Full-text search
			currentMatches = qe.fullTextSearch(filter.Value.(string))
		} else {
			// Field-specific search
			currentMatches = qe.fieldSearch(filter)
		}

		if i == 0 {
			matchingIndices = currentMatches
		} else {
			// AND operation (intersection)
			matchingIndices = qe.intersect(matchingIndices, currentMatches)
		}
	}

	// Convert indices to events
	var matchingEvents []Envelope
	for _, index := range matchingIndices {
		if index < len(qe.eventStore) {
			matchingEvents = append(matchingEvents, qe.eventStore[index])
		}
	}

	return matchingEvents
}

// fieldSearch searches for events matching a specific field filter
func (qe *QueryEngine) fieldSearch(filter QueryFilter) []int {
	var matches []int

	switch filter.Operator {
	case "eq":
		if indices, exists := qe.indexedFields[filter.Field][filter.Value.(string)]; exists {
			matches = indices
		}
	case "contains":
		pattern := strings.ToLower(filter.Value.(string))
		for value, indices := range qe.indexedFields[filter.Field] {
			if strings.Contains(strings.ToLower(value), pattern) {
				matches = append(matches, indices...)
			}
		}
	case "gt", "lt":
		// Numeric comparison
		targetValue, err := strconv.ParseFloat(filter.Value.(string), 64)
		if err != nil {
			return matches
		}

		for value, indices := range qe.indexedFields[filter.Field] {
			if numValue, err := strconv.ParseFloat(value, 64); err == nil {
				if (filter.Operator == "gt" && numValue > targetValue) ||
					(filter.Operator == "lt" && numValue < targetValue) {
					matches = append(matches, indices...)
				}
			}
		}
	}

	return matches
}

// fullTextSearch performs full-text search across all events
func (qe *QueryEngine) fullTextSearch(searchTerm string) []int {
	var matches []int
	searchTerm = strings.ToLower(searchTerm)

	for i, event := range qe.eventStore {
		eventJSON, _ := json.Marshal(event)
		eventText := strings.ToLower(string(eventJSON))

		if strings.Contains(eventText, searchTerm) {
			matches = append(matches, i)
		}
	}

	return matches
}

// intersect finds common elements between two slices
func (qe *QueryEngine) intersect(a, b []int) []int {
	var result []int
	m := make(map[int]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if m[item] {
			result = append(result, item)
		}
	}

	return result
}

// calculateAggregations calculates aggregations for the matching events
func (qe *QueryEngine) calculateAggregations(events []Envelope) map[string]interface{} {
	aggregations := make(map[string]interface{})

	// Count by event class
	classCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	assetCounts := make(map[string]int)

	for _, event := range events {
		// Event class aggregation
		if class, ok := event.Event["class"].(string); ok {
			classCounts[class]++
		}

		// Severity aggregation
		if severity, ok := event.Event["severity"].(float64); ok {
			severityStr := fmt.Sprintf("%.0f", severity)
			severityCounts[severityStr]++
		}

		// Asset type aggregation
		if assetType, ok := event.Asset["type"]; ok {
			assetCounts[assetType]++
		}
	}

	aggregations["event_classes"] = classCounts
	aggregations["severities"] = severityCounts
	aggregations["asset_types"] = assetCounts

	// Time-based aggregation (events per hour)
	timeAgg := make(map[string]int)
	for _, event := range events {
		if eventTime, err := time.Parse(time.RFC3339, event.Ts); err == nil {
			hour := eventTime.Format("2006-01-02T15:00:00Z")
			timeAgg[hour]++
		}
	}
	aggregations["timeline"] = timeAgg

	return aggregations
}

// GetStoredEvents returns all stored events (for debugging)
func (qe *QueryEngine) GetStoredEvents() []Envelope {
	return qe.eventStore
}

// GetEventCount returns the number of stored events
func (qe *QueryEngine) GetEventCount() int {
	return len(qe.eventStore)
}

// ClearEvents clears all stored events
func (qe *QueryEngine) ClearEvents() {
	qe.eventStore = qe.eventStore[:0]
	qe.indexedFields = make(map[string]map[string][]int)
}

// getNestedValue safely gets a nested value from a map
func getNestedValue(m map[string]interface{}, key string) string {
	if value, exists := m[key]; exists {
		return fmt.Sprintf("%v", value)
	}
	return ""
}
