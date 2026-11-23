package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	rules "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
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
}

func result(ordinal int, alert bool) decision {
	return decision{Ordinal: ordinal, Alert: &alert}
}

func inspect(waf coraza.WAF, row observation) decision {
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
		return result(row.Ordinal, true)
	}
	if interruption, _, err := tx.WriteRequestBody([]byte(row.Body)); err != nil {
		return unknown
	} else if interruption != nil {
		return result(row.Ordinal, true)
	}
	interruption, err := tx.ProcessRequestBody()
	if err != nil {
		return unknown
	}
	return result(row.Ordinal, interruption != nil)
}

func run() error {
	config := coraza.NewWAFConfig().WithRootFS(rules.FS).
		WithDirectivesFromFile("@coraza.conf-recommended").
		WithDirectives("SecRuleEngine On\nSecAuditEngine Off\nSecDebugLogLevel 0").
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
		if err := encoder.Encode(inspect(waf, row)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
