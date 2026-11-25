package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	rules "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type observation struct {
	Ordinal  int               `json:"ordinal"`
	Target   string            `json:"target"`
	Method   string            `json:"method"`
	Protocol string            `json:"protocol"`
	Client   string            `json:"client"`
	Server   string            `json:"server"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
}

type decision struct {
	Ordinal int   `json:"ordinal"`
	Alert   *bool `json:"alert"`
	RuleIDs []int `json:"rule_ids,omitempty"`
}

func matchedAttackIDs(tx types.Transaction) []int {
	var ids []int
	for _, matched := range tx.MatchedRules() {
		rule := matched.Rule()
		if slices.ContainsFunc(rule.Tags(), func(tag string) bool { return strings.HasPrefix(tag, "attack-") }) {
			ids = append(ids, rule.ID())
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// Ignore header/protocol enforcement when only the saved request target is known.
func inspectTarget(waf coraza.WAF, row observation) decision {
	value := decision{Ordinal: row.Ordinal}
	if row.Ordinal < 1 || row.Target == "" || len(row.Target) > 16384 ||
		strings.ContainsAny(row.Target, "\x00\r\n") ||
		!slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}, row.Method) {
		return value
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessURI(row.Target, row.Method, row.Protocol)
	tx.ProcessRequestHeaders()
	// CRS places request-target checks in both request phases. The body stays empty.
	if _, err := tx.ProcessRequestBody(); err != nil {
		return value
	}
	for _, match := range tx.MatchedRules() {
		rule := match.Rule()
		if slices.ContainsFunc(rule.Tags(), func(tag string) bool {
			return slices.Contains([]string{
				"attack-sqli", "attack-xss", "attack-rce", "attack-lfi", "attack-rfi",
			}, tag)
		}) {
			value.RuleIDs = append(value.RuleIDs, rule.ID())
		}
	}
	slices.Sort(value.RuleIDs)
	value.RuleIDs = slices.Compact(value.RuleIDs)
	alert := len(value.RuleIDs) > 0
	value.Alert = &alert
	return value
}

func result(tx types.Transaction, ordinal int, alert bool, ruleIDs bool) decision {
	value := decision{Ordinal: ordinal, Alert: &alert}
	if ruleIDs {
		value.RuleIDs = matchedAttackIDs(tx)
	}
	return value
}

func inspect(waf coraza.WAF, row observation, ruleIDs bool) decision {
	unknown := decision{Ordinal: row.Ordinal}
	if row.Ordinal < 1 || row.Method != "POST" || row.Target == "" ||
		len(row.Body) > 1048576 || !strings.HasPrefix(row.Protocol, "HTTP/") {
		return unknown
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(row.Client, 0, row.Server, 0)
	tx.ProcessURI(row.Target, row.Method, row.Protocol)
	for name, value := range row.Headers {
		if strings.ContainsAny(value, "\x00\r\n") {
			return unknown
		}
		tx.AddRequestHeader(name, value)
	}
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return result(tx, row.Ordinal, true, ruleIDs)
	}
	if interruption, _, err := tx.WriteRequestBody([]byte(row.Body)); err != nil {
		return unknown
	} else if interruption != nil {
		return result(tx, row.Ordinal, true, ruleIDs)
	}
	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		return unknown
	}
	return result(tx, row.Ordinal, interruption != nil, ruleIDs)
}

func run(ruleIDs, targetOnly bool) error {
	mode := "On"
	if targetOnly {
		mode = "DetectionOnly"
	}
	config := coraza.NewWAFConfig().WithRootFS(rules.FS).
		WithDirectivesFromFile("@coraza.conf-recommended").
		WithDirectives("SecRuleEngine " + mode + "\nSecAuditEngine Off\nSecDebugLogLevel 0").
		WithDirectivesFromFile("@crs-setup.conf.example").
		WithDirectivesFromFile("@owasp_crs/*.conf")
	waf, err := coraza.NewWAF(config)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 12000000)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	encoder := json.NewEncoder(writer)
	for scanner.Scan() {
		var row observation
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return fmt.Errorf("invalid local observation")
		}
		var value decision
		if targetOnly {
			value = inspectTarget(waf, row)
		} else {
			value = inspect(waf, row, ruleIDs)
		}
		if err := encoder.Encode(value); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func main() {
	ruleIDs := flag.Bool("rule-ids", false, "include matching CRS attack rule IDs in local output")
	targetOnly := flag.Bool("target-only", false, "collect content signals from saved request targets")
	flag.Parse()
	if err := run(*ruleIDs, *targetOnly); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
