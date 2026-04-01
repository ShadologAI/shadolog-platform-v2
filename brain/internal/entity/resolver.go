package entity

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/shadologai/shadolog/v2/shared/models"
)

// Resolver extracts entities from events and persists them via Store.
type Resolver struct {
	store  *Store
	logger *slog.Logger
}

// NewResolver creates an entity resolver.
func NewResolver(store *Store, logger *slog.Logger) *Resolver {
	return &Resolver{store: store, logger: logger}
}

// ProcessInventoryEvent handles ARGUS inventory events by creating entities directly.
// Returns true if the event was an inventory type (skip detection pipeline).
func (r *Resolver) ProcessInventoryEvent(ctx context.Context, event *models.Event) bool {
	if r.store == nil || event.TenantID == "" {
		return false
	}

	// Get original event type from metadata
	originalType := event.EventType
	if event.Metadata != nil {
		var meta map[string]any
		if json.Unmarshal(event.Metadata, &meta) == nil {
			if ot, ok := meta["original_event_type"].(string); ok && ot != "" {
				originalType = ot
			}
		}
	}

	switch originalType {
	case "endpoint_inventory":
		r.processToolInventory(ctx, event)
		return true
	case "endpoint_mcp_inventory":
		r.processMCPInventory(ctx, event)
		return true
	case "endpoint_permission_map":
		r.processPermissionMap(ctx, event)
		return true
	case "endpoint_forensic_session":
		r.processForensicSession(ctx, event)
		return true
	default:
		return false
	}
}

// ResolveFromEvent extracts entities from a normal event and creates relationships.
// Builds: User -> Agent -> Tool -> Provider correlation chain.
func (r *Resolver) ResolveFromEvent(ctx context.Context, event *models.Event, findings []models.Finding) {
	if r.store == nil || event.TenantID == "" {
		return
	}

	entityIDs := make(map[string]string) // "type" -> entity_id

	if event.UserID != "" {
		id, err := r.store.UpsertEntity(ctx, event.TenantID, "user", event.UserID,
			map[string]any{"email": event.UserID}, 0, event.AgentType)
		if err == nil {
			entityIDs["user"] = id
		}
	}

	if event.AgentID != "" {
		id, err := r.store.UpsertEntity(ctx, event.TenantID, "agent", event.AgentID,
			map[string]any{"agent_type": event.AgentType}, 0, event.AgentType)
		if err == nil {
			entityIDs["agent"] = id
		}
	}

	if event.AITool != "" {
		id, err := r.store.UpsertEntity(ctx, event.TenantID, "tool", event.AITool,
			map[string]any{"tool_type": ClassifyAITool(event.AITool)}, 0, event.AgentType)
		if err == nil {
			entityIDs["tool"] = id
		}
	}

	if event.URL != "" {
		provider := ExtractProvider(event.URL)
		if provider != "" {
			id, err := r.store.UpsertEntity(ctx, event.TenantID, "ai_provider", provider,
				map[string]any{"provider_type": provider, "api_base_url": event.URL}, 0, event.AgentType)
			if err == nil {
				entityIDs["ai_provider"] = id
			}
		}
	}

	// Resolve MCP server entity from hook bridge events
	if event.MCPServerURL != "" || event.MCPToolName != "" {
		mcpName := event.MCPToolName
		if mcpName == "" {
			mcpName = event.MCPServerURL
		}
		id, err := r.store.UpsertEntity(ctx, event.TenantID, "mcp_server", mcpName,
			map[string]any{"url": event.MCPServerURL, "transport": "stdio"}, 10, event.AgentType)
		if err == nil {
			entityIDs["mcp_server"] = id
		}
	}

	// Determine risk from findings
	riskLevel := "low"
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			riskLevel = "critical"
		case "high":
			if riskLevel != "critical" {
				riskLevel = "high"
			}
		case "medium":
			if riskLevel != "critical" && riskLevel != "high" {
				riskLevel = "medium"
			}
		}
	}

	// Relationships
	if uid, ok := entityIDs["user"]; ok {
		if aid, ok := entityIDs["agent"]; ok {
			r.store.UpsertRelationship(ctx, event.TenantID, uid, aid, "manages", "low", nil)
		}
		if tid, ok := entityIDs["tool"]; ok {
			r.store.UpsertRelationship(ctx, event.TenantID, uid, tid, "uses", riskLevel, nil)
		}
	}
	if aid, ok := entityIDs["agent"]; ok {
		if tid, ok := entityIDs["tool"]; ok {
			r.store.UpsertRelationship(ctx, event.TenantID, aid, tid, "invokes", "low", nil)
		}
	}
	if tid, ok := entityIDs["tool"]; ok {
		if pid, ok := entityIDs["ai_provider"]; ok {
			r.store.UpsertRelationship(ctx, event.TenantID, tid, pid, "connects_to", "low", nil)
		}
		if mid, ok := entityIDs["mcp_server"]; ok {
			r.store.UpsertRelationship(ctx, event.TenantID, tid, mid, "uses", "low", nil)
		}
	}
}

// --- Inventory event handlers ---

func (r *Resolver) processToolInventory(ctx context.Context, event *models.Event) {
	var inv struct {
		ToolName   string   `json:"tool_name"`
		Confidence float64  `json:"confidence"`
		IsRunning  bool     `json:"is_running"`
		PIDs       []int    `json:"pids"`
		Networks   []string `json:"networks,omitempty"`
	}

	// Content is the raw_content which is JSON-serialized content map
	content := parseContent(event.RawContent)

	// ARGUS sends ai.service as the tool name at event level
	toolName := event.AITool
	if toolName == "" {
		if tn, ok := content["tool_name"].(string); ok {
			toolName = tn
		}
	}
	if toolName == "" {
		return
	}

	if err := mapToStruct(content, &inv); err != nil {
		// Use event-level fields
		inv.ToolName = toolName
	}

	hostname := event.UserID // ARGUS sends "device:hostname" as user_id
	if hostname == "" {
		hostname = event.AgentID
	}
	if hostname == "" {
		hostname = "unknown-endpoint"
	}

	agentID, _ := r.store.UpsertEntity(ctx, event.TenantID, "agent", hostname,
		map[string]any{"agent_type": "endpoint_sensor", "source": "argus_sweep"}, 0, "endpoint_sensor")

	toolID, _ := r.store.UpsertEntity(ctx, event.TenantID, "tool", toolName,
		map[string]any{
			"tool_type":  ClassifyAITool(toolName),
			"running":    inv.IsRunning,
			"confidence": inv.Confidence,
		}, 0, "endpoint_sensor")

	if agentID != "" && toolID != "" {
		r.store.UpsertRelationship(ctx, event.TenantID, agentID, toolID, "invokes", "low", nil)
	}

	// Extract provider and data sink entities from network connections
	networks, _ := content["networks"].([]any)
	for _, n := range networks {
		if net, ok := n.(string); ok {
			provider := ExtractProvider(net)
			if provider != "" {
				pid, _ := r.store.UpsertEntity(ctx, event.TenantID, "ai_provider", provider,
					map[string]any{"provider_type": provider, "api_base_url": net}, 0, "endpoint_sensor")
				if toolID != "" && pid != "" {
					r.store.UpsertRelationship(ctx, event.TenantID, toolID, pid, "connects_to", "low", nil)
				}
			}

			// Check for data sink destinations
			sinkName, sinkRisk := ExtractDataSink(net)
			if sinkName != "" {
				sinkID, _ := r.store.UpsertEntity(ctx, event.TenantID, "data_sink", sinkName,
					map[string]any{"url": net, "sink_type": "external"}, sinkRisk, "endpoint_sensor")
				if toolID != "" && sinkID != "" {
					riskLevel := "low"
					if sinkRisk >= 60 {
						riskLevel = "high"
					} else if sinkRisk >= 30 {
						riskLevel = "medium"
					}
					r.store.UpsertRelationship(ctx, event.TenantID, toolID, sinkID, "sends_data_to", riskLevel, nil)
				}
			}
		}
	}

	r.logger.Info("inventory entity created", "tool", toolName, "tenant_id", event.TenantID)
}

func (r *Resolver) processMCPInventory(ctx context.Context, event *models.Event) {
	content := parseContent(event.RawContent)

	name, _ := content["name"].(string)
	if name == "" {
		name = event.AITool
	}
	if name == "" {
		return
	}

	transport, _ := content["transport"].(string)
	if transport == "" {
		transport = "stdio"
	}

	source, _ := content["source"].(string)
	url, _ := content["url"].(string)
	configPath, _ := content["config_path"].(string)

	riskScore := int16(10)
	if (transport == "http" || transport == "sse") && url != "" {
		if !strings.Contains(url, "localhost") && !strings.Contains(url, "127.0.0.1") {
			riskScore = 60
		}
	}

	mcpID, _ := r.store.UpsertEntity(ctx, event.TenantID, "mcp_server", name,
		map[string]any{
			"url":                 url,
			"transport":           transport,
			"auth_type":           "none",
			"discovered_by":       source,
			"config_path":         configPath,
			"is_internet_exposed": riskScore > 30,
		}, riskScore, "endpoint_sensor")

	// Link MCP to its parent agent
	if mcpID != "" && source != "" {
		agentKey := MCPSourceToAgentKey(source)
		if agentKey != "" {
			agentID, _ := r.store.UpsertEntity(ctx, event.TenantID, "agent", agentKey,
				map[string]any{"agent_type": ClassifyAITool(agentKey), "source": "mcp_inventory"}, 0, "endpoint_sensor")
			if agentID != "" {
				r.store.UpsertRelationship(ctx, event.TenantID, agentID, mcpID, "uses", "low", nil)
			}
		}
	}

	r.logger.Info("mcp entity created", "name", name, "tenant_id", event.TenantID)
}

func (r *Resolver) processPermissionMap(ctx context.Context, event *models.Event) {
	content := parseContent(event.RawContent)

	hostname, _ := content["hostname"].(string)

	// Parse agents
	agentIDs := make(map[string]string)
	if agents, ok := content["agents"].([]any); ok {
		for _, a := range agents {
			agent, ok := a.(map[string]any)
			if !ok {
				continue
			}
			agentKey, _ := agent["agent_key"].(string)
			displayName, _ := agent["display_name"].(string)
			isRunning, _ := agent["is_running"].(bool)

			id, err := r.store.UpsertEntity(ctx, event.TenantID, "agent", agentKey,
				map[string]any{
					"agent_type":   ClassifyAITool(agentKey),
					"display_name": displayName,
					"running":      isRunning,
					"source":       "permission_map",
					"hostname":     hostname,
				}, 0, "endpoint_sensor")
			if err == nil {
				agentIDs[agentKey] = id
			}

			// Agent → MCP relationships
			if mcpServers, ok := agent["mcp_servers"].([]any); ok {
				for _, m := range mcpServers {
					mcp, ok := m.(map[string]any)
					if !ok {
						continue
					}
					serverName, _ := mcp["server_name"].(string)
					mcpURL, _ := mcp["url"].(string)
					mcpSource, _ := mcp["source"].(string)
					mcpType, _ := mcp["type"].(string)

					riskScore := int16(10)
					if (mcpType == "http" || mcpType == "sse") && mcpURL != "" {
						if !strings.Contains(mcpURL, "localhost") && !strings.Contains(mcpURL, "127.0.0.1") {
							riskScore = 60
						}
					}

					mcpID, _ := r.store.UpsertEntity(ctx, event.TenantID, "mcp_server", serverName,
						map[string]any{
							"url":                 mcpURL,
							"transport":           mcpType,
							"discovered_by":       mcpSource,
							"is_internet_exposed": riskScore > 30,
						}, riskScore, "endpoint_sensor")

					if id != "" && mcpID != "" {
						r.store.UpsertRelationship(ctx, event.TenantID, id, mcpID, "uses", "low", nil)
					}
				}
			}
		}
	}

	// Parse delegation chains with circular detection
	delegationGraph := make(map[string][]string) // from → [to, to, ...]
	if delegations, ok := content["delegations"].([]any); ok {
		for _, d := range delegations {
			del, ok := d.(map[string]any)
			if !ok {
				continue
			}
			fromAgent, _ := del["from_agent"].(string)
			toAgent, _ := del["to_agent"].(string)
			method, _ := del["method"].(string)

			// N5: Track inherited permissions
			var inheritedPerms []string
			if permsRaw, ok := del["inherited_perms"].([]any); ok {
				for _, p := range permsRaw {
					if s, ok := p.(string); ok {
						inheritedPerms = append(inheritedPerms, s)
					}
				}
			}

			fromID := agentIDs[fromAgent]
			toID := agentIDs[toAgent]
			if fromID == "" || toID == "" {
				continue
			}

			delegationGraph[fromAgent] = append(delegationGraph[fromAgent], toAgent)

			riskLevel := "low"
			if method == "terminal_inheritance" {
				riskLevel = "medium"
			}
			// Escalate risk if many permissions inherited (permission explosion)
			if len(inheritedPerms) > 5 {
				riskLevel = "high"
				r.logger.Warn("permission explosion detected",
					"from", fromAgent, "to", toAgent,
					"inherited_count", len(inheritedPerms),
					"tenant_id", event.TenantID,
				)
			}

			meta := map[string]any{"method": method}
			if len(inheritedPerms) > 0 {
				meta["inherited_perms"] = inheritedPerms
				meta["inherited_count"] = len(inheritedPerms)
			}

			r.store.UpsertRelationship(ctx, event.TenantID, fromID, toID, "delegates_to",
				riskLevel, meta)
		}
	}

	// Detect circular delegation chains (A→B→C→A) and flag as high risk
	for startAgent := range delegationGraph {
		if cycle := detectCycle(delegationGraph, startAgent); cycle != nil {
			r.logger.Warn("circular delegation chain detected",
				"tenant_id", event.TenantID,
				"cycle", strings.Join(cycle, " → "),
				"hostname", hostname,
			)
			// Elevate risk on all agents in the cycle
			for _, agent := range cycle {
				if id, ok := agentIDs[agent]; ok {
					r.store.UpsertEntity(ctx, event.TenantID, "agent", agent,
						map[string]any{"circular_delegation": true, "delegation_cycle": strings.Join(cycle, " → ")},
						40, "endpoint_sensor")
					_ = id
				}
			}
			break // One cycle detection per permission map is enough
		}
	}

	r.logger.Info("permission map entities created",
		"tenant_id", event.TenantID,
		"agents", len(agentIDs),
		"delegations", len(delegationGraph),
		"hostname", hostname,
	)
}

func (r *Resolver) processForensicSession(ctx context.Context, event *models.Event) {
	content := parseContent(event.RawContent)

	username, _ := content["username"].(string)
	model, _ := content["model"].(string)

	var userID string
	if username != "" {
		userID, _ = r.store.UpsertEntity(ctx, event.TenantID, "user", username,
			map[string]any{"email": username, "source": "forensic_transcript"}, 0, "endpoint_sensor")
	}

	toolID, _ := r.store.UpsertEntity(ctx, event.TenantID, "tool", "claude_code",
		map[string]any{"tool_type": "cli_tool", "model": model}, 0, "endpoint_sensor")

	providerID, _ := r.store.UpsertEntity(ctx, event.TenantID, "ai_provider", "anthropic",
		map[string]any{"provider_type": "anthropic"}, 0, "endpoint_sensor")

	if userID != "" && toolID != "" {
		r.store.UpsertRelationship(ctx, event.TenantID, userID, toolID, "uses", "low", nil)
	}
	if toolID != "" && providerID != "" {
		r.store.UpsertRelationship(ctx, event.TenantID, toolID, providerID, "connects_to", "low", nil)
	}

	// MCP servers from transcript
	if mcpServers, ok := content["mcp_servers"].([]any); ok {
		for _, m := range mcpServers {
			if name, ok := m.(string); ok {
				mcpID, _ := r.store.UpsertEntity(ctx, event.TenantID, "mcp_server", name,
					map[string]any{"transport": "stdio", "discovered_by": "transcript"}, 10, "endpoint_sensor")
				if toolID != "" && mcpID != "" {
					r.store.UpsertRelationship(ctx, event.TenantID, toolID, mcpID, "uses", "low", nil)
				}
			}
		}
	}
}

// --- Helpers ---

func parseContent(raw string) map[string]any {
	var m map[string]any
	json.Unmarshal([]byte(raw), &m)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func mapToStruct(m map[string]any, dest any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

// detectCycle performs DFS from start to find a cycle in the delegation graph.
// Returns the cycle path if found, nil otherwise.
func detectCycle(graph map[string][]string, start string) []string {
	visited := map[string]bool{}
	path := []string{}

	var dfs func(node string) []string
	dfs = func(node string) []string {
		if visited[node] {
			// Found cycle — extract it
			for i, p := range path {
				if p == node {
					cycle := append([]string{}, path[i:]...)
					cycle = append(cycle, node)
					return cycle
				}
			}
			return nil
		}
		visited[node] = true
		path = append(path, node)

		for _, next := range graph[node] {
			if result := dfs(next); result != nil {
				return result
			}
		}

		path = path[:len(path)-1]
		return nil
	}

	return dfs(start)
}
