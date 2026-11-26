package main

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestPassiveBodyUsesOnlySupportedObservedType(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule ARGS:probe "@streq harmless-example" "id:1,phase:2,pass,tag:'attack-rce'"
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType, encoding string
		includeBody, expected       bool
	}{
		{"observed form", "application/x-www-form-urlencoded", "", true, true},
		{"target-only", "application/x-www-form-urlencoded", "", false, false},
		{"missing type", "", "", true, false},
		{"different type", "text/plain", "", true, false},
		{"invalid type", "application/x-www-form-urlencoded\r\n", "", true, false},
		{"different encoding", "application/x-www-form-urlencoded", "gzip", true, false},
		{"different charset", "application/x-www-form-urlencoded; charset=latin1", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := observation{Ordinal: 1, Target: "/record", Method: "POST", Protocol: "HTTP/1.1",
				Body: "probe=harmless-example", Headers: map[string]string{"Content-Type": tc.contentType, "Content-Encoding": tc.encoding}}
			result := inspectTarget(waf, row, tc.includeBody)
			if result.BodyIncluded != tc.expected || result.Alert == nil || *result.Alert != tc.expected {
				t.Fatalf("expected body inclusion and matching marker = %v, got %+v", tc.expected, result)
			}
		})
	}
}
