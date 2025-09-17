package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type GraphService struct {
	driver neo4j.DriverWithContext
	ctx    context.Context
}

type GraphNode struct {
	ID         string                 `json:"id"`
	Labels     []string               `json:"labels"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

type GraphRelationship struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	StartNode  string                 `json:"start_node"`
	EndNode    string                 `json:"end_node"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
}

type GraphQuery struct {
	Query      string                 `json:"query"`
	Parameters map[string]interface{} `json:"parameters"`
	Limit      int                    `json:"limit"`
}

type GraphResult struct {
	Nodes         []GraphNode         `json:"nodes"`
	Relationships []GraphRelationship `json:"relationships"`
	Statistics    map[string]int64    `json:"statistics"`
	ExecutionTime int64               `json:"execution_time_ms"`
}

type ThreatGraph struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Nodes       []GraphNode         `json:"nodes"`
	Edges       []GraphRelationship `json:"edges"`
	RiskScore   float64             `json:"risk_score"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

type AttackPath struct {
	ID          string    `json:"id"`
	Path        []string  `json:"path"`
	RiskScore   float64   `json:"risk_score"`
	ThreatType  string    `json:"threat_type"`
	Description string    `json:"description"`
	Mitigation  []string  `json:"mitigation_steps"`
	CreatedAt   time.Time `json:"created_at"`
}

type GraphInsight struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // anomaly, pattern, threat, recommendation
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Nodes       []string               `json:"affected_nodes"`
	Edges       []string               `json:"affected_edges"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

func NewGraphService() *GraphService {
	uri := os.Getenv("NEO4J_URI")
	if uri == "" {
		uri = "bolt://localhost:7687"
	}

	username := os.Getenv("NEO4J_USERNAME")
	if username == "" {
		username = "neo4j"
	}

	password := os.Getenv("NEO4J_PASSWORD")
	if password == "" {
		password = "password"
	}

	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		log.Fatalf("Failed to create Neo4j driver: %v", err)
	}

	ctx := context.Background()

	// Test connection
	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to Neo4j: %v", err)
	}

	return &GraphService{
		driver: driver,
		ctx:    ctx,
	}
}

func (g *GraphService) CreateNode(node GraphNode) error {
	session := g.driver.NewSession(g.ctx, neo4j.SessionConfig{})
	defer session.Close(g.ctx)

	query := `
		CREATE (n:Node {id: $id, properties: $properties, created_at: $created_at, updated_at: $updated_at})
		SET n += $labels
	`

	_, err := session.Run(g.ctx, query, map[string]interface{}{
		"id":         node.ID,
		"labels":     node.Labels,
		"properties": node.Properties,
		"created_at": node.CreatedAt,
		"updated_at": node.UpdatedAt,
	})

	return err
}

func (g *GraphService) CreateRelationship(rel GraphRelationship) error {
	session := g.driver.NewSession(g.ctx, neo4j.SessionConfig{})
	defer session.Close(g.ctx)

	query := `
		MATCH (a:Node {id: $start_node})
		MATCH (b:Node {id: $end_node})
		CREATE (a)-[r:RELATIONSHIP {id: $id, type: $type, properties: $properties, created_at: $created_at}]->(b)
	`

	_, err := session.Run(g.ctx, query, map[string]interface{}{
		"id":         rel.ID,
		"type":       rel.Type,
		"start_node": rel.StartNode,
		"end_node":   rel.EndNode,
		"properties": rel.Properties,
		"created_at": rel.CreatedAt,
	})

	return err
}

func (g *GraphService) ExecuteQuery(query GraphQuery) (*GraphResult, error) {
	session := g.driver.NewSession(g.ctx, neo4j.SessionConfig{})
	defer session.Close(g.ctx)

	start := time.Now()
	result, err := session.Run(g.ctx, query.Query, query.Parameters)
	if err != nil {
		return nil, err
	}

	records, err := result.Collect(g.ctx)
	if err != nil {
		return nil, err
	}

	executionTime := time.Since(start).Milliseconds()

	graphResult := &GraphResult{
		Nodes:         []GraphNode{},
		Relationships: []GraphRelationship{},
		Statistics:    make(map[string]int64),
		ExecutionTime: executionTime,
	}

	// Process records
	for _, record := range records {
		// Extract nodes
		for _, value := range record.Values {
			if node, ok := value.(neo4j.Node); ok {
				graphNode := GraphNode{
					ID:         node.Props["id"].(string),
					Labels:     node.Labels,
					Properties: node.Props,
				}
				graphResult.Nodes = append(graphResult.Nodes, graphNode)
			}

			// Extract relationships
			if rel, ok := value.(neo4j.Relationship); ok {
				graphRel := GraphRelationship{
					ID:         rel.Props["id"].(string),
					Type:       rel.Type,
					StartNode:  rel.StartNodeId,
					EndNode:    rel.EndNodeId,
					Properties: rel.Props,
				}
				graphResult.Relationships = append(graphResult.Relationships, graphRel)
			}
		}
	}

	return graphResult, nil
}

func (g *GraphService) FindAttackPaths(startNode, endNode string, maxDepth int) ([]AttackPath, error) {
	query := GraphQuery{
		Query: `
			MATCH path = (start:Node {id: $start_node})-[*1..$max_depth]-(end:Node {id: $end_node})
			WHERE ALL(r in relationships(path) WHERE r.type IN ['ACCESSES', 'COMMUNICATES_WITH', 'EXECUTES', 'MODIFIES'])
			RETURN path, length(path) as path_length
			ORDER BY path_length ASC
			LIMIT 10
		`,
		Parameters: map[string]interface{}{
			"start_node": startNode,
			"end_node":   endNode,
			"max_depth":  maxDepth,
		},
	}

	result, err := g.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	attackPaths := make([]AttackPath, 0)
	for i, node := range result.Nodes {
		path := AttackPath{
			ID:         generatePathID(),
			Path:       []string{node.ID},
			RiskScore:  g.calculatePathRisk(node.Properties),
			ThreatType: g.identifyThreatType(node.Properties),
			CreatedAt:  time.Now(),
		}

		// Add mitigation steps
		path.Mitigation = g.generateMitigationSteps(path.ThreatType)

		attackPaths = append(attackPaths, path)
	}

	return attackPaths, nil
}

func (g *GraphService) DetectAnomalies() ([]GraphInsight, error) {
	insights := make([]GraphInsight, 0)

	// Detect unusual access patterns
	accessAnomalies, err := g.detectAccessAnomalies()
	if err != nil {
		return nil, err
	}
	insights = append(insights, accessAnomalies...)

	// Detect privilege escalation patterns
	privEscalation, err := g.detectPrivilegeEscalation()
	if err != nil {
		return nil, err
	}
	insights = append(insights, privEscalation...)

	// Detect lateral movement
	lateralMovement, err := g.detectLateralMovement()
	if err != nil {
		return nil, err
	}
	insights = append(insights, lateralMovement...)

	// Detect data exfiltration patterns
	dataExfiltration, err := g.detectDataExfiltration()
	if err != nil {
		return nil, err
	}
	insights = append(insights, dataExfiltration...)

	return insights, nil
}

func (g *GraphService) detectAccessAnomalies() ([]GraphInsight, error) {
	query := GraphQuery{
		Query: `
			MATCH (user:User)-[r:ACCESSES]->(asset:Asset)
			WHERE r.timestamp > datetime() - duration('P1D')
			WITH user, asset, count(r) as access_count
			WHERE access_count > 100
			RETURN user, asset, access_count
		`,
	}

	result, err := g.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	insights := make([]GraphInsight, 0)
	for _, node := range result.Nodes {
		insight := GraphInsight{
			ID:          generateInsightID(),
			Type:        "anomaly",
			Title:       "Unusual Access Pattern Detected",
			Description: "User has accessed asset an unusually high number of times",
			Confidence:  0.8,
			Severity:    "medium",
			Nodes:       []string{node.ID},
			CreatedAt:   time.Now(),
			Metadata: map[string]interface{}{
				"access_count": node.Properties["access_count"],
				"threshold":    100,
			},
		}
		insights = append(insights, insight)
	}

	return insights, nil
}

func (g *GraphService) detectPrivilegeEscalation() ([]GraphInsight, error) {
	query := GraphQuery{
		Query: `
			MATCH (user:User)-[r1:ACCESSES]->(asset:Asset)-[r2:EXECUTES]->(process:Process)
			WHERE r1.privilege_level < r2.privilege_level
			AND r1.timestamp < r2.timestamp
			RETURN user, asset, process, r1.privilege_level as old_level, r2.privilege_level as new_level
		`,
	}

	result, err := g.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	insights := make([]GraphInsight, 0)
	for _, node := range result.Nodes {
		insight := GraphInsight{
			ID:          generateInsightID(),
			Type:        "threat",
			Title:       "Privilege Escalation Detected",
			Description: "User escalated privileges on asset",
			Confidence:  0.9,
			Severity:    "high",
			Nodes:       []string{node.ID},
			CreatedAt:   time.Now(),
			Metadata: map[string]interface{}{
				"old_level": node.Properties["old_level"],
				"new_level": node.Properties["new_level"],
			},
		}
		insights = append(insights, insight)
	}

	return insights, nil
}

func (g *GraphService) detectLateralMovement() ([]GraphInsight, error) {
	query := GraphQuery{
		Query: `
			MATCH (user:User)-[r1:ACCESSES]->(asset1:Asset)-[r2:COMMUNICATES_WITH]->(asset2:Asset)
			WHERE r1.timestamp < r2.timestamp
			AND duration.between(r1.timestamp, r2.timestamp).hours < 1
			RETURN user, asset1, asset2, r1.timestamp as start_time, r2.timestamp as end_time
		`,
	}

	result, err := g.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	insights := make([]GraphInsight, 0)
	for _, node := range result.Nodes {
		insight := GraphInsight{
			ID:          generateInsightID(),
			Type:        "threat",
			Title:       "Lateral Movement Detected",
			Description: "User moved between assets in suspicious pattern",
			Confidence:  0.85,
			Severity:    "high",
			Nodes:       []string{node.ID},
			CreatedAt:   time.Now(),
			Metadata: map[string]interface{}{
				"start_time": node.Properties["start_time"],
				"end_time":   node.Properties["end_time"],
			},
		}
		insights = append(insights, insight)
	}

	return insights, nil
}

func (g *GraphService) detectDataExfiltration() ([]GraphInsight, error) {
	query := GraphQuery{
		Query: `
			MATCH (user:User)-[r1:ACCESSES]->(file:File)-[r2:MODIFIES]->(network:Network)
			WHERE r1.timestamp < r2.timestamp
			AND file.size > 1000000
			AND network.destination_type = 'external'
			RETURN user, file, network, file.size as file_size
		`,
	}

	result, err := g.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	insights := make([]GraphInsight, 0)
	for _, node := range result.Nodes {
		insight := GraphInsight{
			ID:          generateInsightID(),
			Type:        "threat",
			Title:       "Data Exfiltration Detected",
			Description: "Large file accessed and transmitted externally",
			Confidence:  0.9,
			Severity:    "critical",
			Nodes:       []string{node.ID},
			CreatedAt:   time.Now(),
			Metadata: map[string]interface{}{
				"file_size": node.Properties["file_size"],
			},
		}
		insights = append(insights, insight)
	}

	return insights, nil
}

func (g *GraphService) BuildThreatGraph(nodes []string, timeWindow time.Duration) (*ThreatGraph, error) {
	query := GraphQuery{
		Query: `
			MATCH (n:Node)
			WHERE n.id IN $node_ids
			OPTIONAL MATCH (n)-[r]-(m:Node)
			WHERE r.timestamp > datetime() - duration($time_window)
			RETURN n, r, m
		`,
		Parameters: map[string]interface{}{
			"node_ids":    nodes,
			"time_window": timeWindow.String(),
		},
	}

	result, err := g.ExecuteQuery(query)
	if err != nil {
		return nil, err
	}

	threatGraph := &ThreatGraph{
		ID:          generateThreatGraphID(),
		Title:       "Threat Graph Analysis",
		Description: "Graph-based threat analysis for selected nodes",
		Nodes:       result.Nodes,
		Edges:       result.Relationships,
		RiskScore:   g.calculateThreatGraphRisk(result.Nodes, result.Relationships),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return threatGraph, nil
}

func (g *GraphService) calculatePathRisk(properties map[string]interface{}) float64 {
	// Calculate risk based on node properties
	risk := 0.0

	if privilege, ok := properties["privilege_level"].(int); ok {
		risk += float64(privilege) * 0.2
	}

	if sensitive, ok := properties["sensitive"].(bool); ok && sensitive {
		risk += 0.3
	}

	if external, ok := properties["external"].(bool); ok && external {
		risk += 0.2
	}

	return math.Min(risk, 1.0)
}

func (g *GraphService) identifyThreatType(properties map[string]interface{}) string {
	// Identify threat type based on properties
	if privilege, ok := properties["privilege_level"].(int); ok && privilege > 5 {
		return "privilege_escalation"
	}

	if external, ok := properties["external"].(bool); ok && external {
		return "data_exfiltration"
	}

	if sensitive, ok := properties["sensitive"].(bool); ok && sensitive {
		return "data_access"
	}

	return "unknown"
}

func (g *GraphService) generateMitigationSteps(threatType string) []string {
	switch threatType {
	case "privilege_escalation":
		return []string{
			"Review user privileges",
			"Implement least privilege principle",
			"Monitor privilege changes",
			"Audit administrative access",
		}
	case "data_exfiltration":
		return []string{
			"Block external data transfers",
			"Implement data loss prevention",
			"Monitor file access patterns",
			"Review data classification",
		}
	case "data_access":
		return []string{
			"Review data access permissions",
			"Implement data encryption",
			"Monitor sensitive data access",
			"Update access controls",
		}
	default:
		return []string{
			"Investigate further",
			"Monitor system",
			"Update security controls",
		}
	}
}

func (g *GraphService) calculateThreatGraphRisk(nodes []GraphNode, edges []GraphRelationship) float64 {
	risk := 0.0

	// Calculate risk based on nodes
	for _, node := range nodes {
		if sensitive, ok := node.Properties["sensitive"].(bool); ok && sensitive {
			risk += 0.3
		}
		if external, ok := node.Properties["external"].(bool); ok && external {
			risk += 0.2
		}
	}

	// Calculate risk based on relationships
	for _, edge := range edges {
		if edge.Type == "EXECUTES" {
			risk += 0.1
		}
		if edge.Type == "MODIFIES" {
			risk += 0.15
		}
	}

	return math.Min(risk, 1.0)
}

func (g *GraphService) Close() error {
	return g.driver.Close(g.ctx)
}

// Utility functions
func generatePathID() string {
	return fmt.Sprintf("path_%d", time.Now().UnixNano())
}

func generateInsightID() string {
	return fmt.Sprintf("insight_%d", time.Now().UnixNano())
}

func generateThreatGraphID() string {
	return fmt.Sprintf("threat_graph_%d", time.Now().UnixNano())
}
