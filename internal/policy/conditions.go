package policy

import (
	"encoding/json"
	"strings"

	"github.com/harris/honeypot/internal/correlation"
)

// ConditionNode represents a single leaf predicate in a rule's JSON condition AST.
type ConditionNode struct {
	Field string `json:"field"`
	Op    string `json:"op"` // eq | ne | in | contains | gt | gte | lt | lte
	Value any    `json:"value"`
}

// ConditionAST represents boolean combinators ("all" AND, "any" OR) over ConditionNodes.
type ConditionAST struct {
	All []ConditionNode `json:"all,omitempty"`
	Any []ConditionNode `json:"any,omitempty"`
}

// EvaluateCondition checks whether inc satisfies conditionsJSON.
func EvaluateCondition(conditionsJSON string, inc correlation.IncidentSnapshot) bool {
	if strings.TrimSpace(conditionsJSON) == "" || strings.TrimSpace(conditionsJSON) == "{}" {
		return false
	}
	var ast ConditionAST
	if err := json.Unmarshal([]byte(conditionsJSON), &ast); err != nil {
		return false
	}
	if len(ast.All) == 0 && len(ast.Any) == 0 {
		return false
	}
	if len(ast.All) > 0 {
		for _, node := range ast.All {
			if !evalLeaf(node, inc) {
				return false
			}
		}
		if len(ast.Any) == 0 {
			return true
		}
	}
	if len(ast.Any) > 0 {
		for _, node := range ast.Any {
			if evalLeaf(node, inc) {
				return true
			}
		}
		return false
	}
	return true
}

func evalLeaf(node ConditionNode, inc correlation.IncidentSnapshot) bool {
	switch node.Field {
	case "greynoise_classification":
		return compareString(inc.GreyNoiseClassification, node.Op, node.Value)
	case "canary_key_used":
		return compareBool(len(inc.CanaryKeyIDs) > 0, node.Op, node.Value)
	case "is_kev":
		return compareBool(inc.IsKEV, node.Op, node.Value)
	case "yara_match_count":
		return compareNumber(float64(inc.YaraMatchCount), node.Op, node.Value)
	case "confidence_score":
		return compareNumber(float64(inc.ConfidenceScore), node.Op, node.Value)
	case "distinct_traps":
		return compareNumber(float64(len(inc.TrapKinds)), node.Op, node.Value)
	case "abuseipdb_score":
		return compareNumber(float64(inc.AbuseIPDBScore), node.Op, node.Value)
	case "ja4":
		return compareString(inc.JA4, node.Op, node.Value)
	case "trap_kind":
		return compareSlice(inc.TrapKinds, node.Op, node.Value)
	case "cve_id":
		return compareSlice(inc.CVEIDs, node.Op, node.Value)
	default:
		return false
	}
}

func compareString(actual, op string, val any) bool {
	switch op {
	case "eq":
		s, _ := val.(string)
		return strings.EqualFold(actual, s)
	case "ne":
		s, _ := val.(string)
		return !strings.EqualFold(actual, s)
	case "contains":
		s, _ := val.(string)
		return strings.Contains(strings.ToLower(actual), strings.ToLower(s))
	case "in":
		arr, ok := val.([]any)
		if !ok {
			return false
		}
		for _, item := range arr {
			if s, ok := item.(string); ok && strings.EqualFold(actual, s) {
				return true
			}
		}
	}
	return false
}

func compareBool(actual bool, op string, val any) bool {
	b, ok := val.(bool)
	if !ok {
		return false
	}
	if op == "eq" {
		return actual == b
	}
	if op == "ne" {
		return actual != b
	}
	return false
}

func compareNumber(actual float64, op string, val any) bool {
	target, ok := toFloat(val)
	if !ok {
		return false
	}
	switch op {
	case "eq":
		return actual == target
	case "gt":
		return actual > target
	case "gte":
		return actual >= target
	case "lt":
		return actual < target
	case "lte":
		return actual <= target
	}
	return false
}

func compareSlice(items []string, op string, val any) bool {
	for _, item := range items {
		if compareString(item, op, val) {
			return true
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		return 0, false
	}
}
