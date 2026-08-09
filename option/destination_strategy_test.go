package option

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"
)

func TestDestinationStrategyJSON(t *testing.T) {
	var emptyStrategy DestinationStrategy
	if err := json.Unmarshal([]byte(`""`), &emptyStrategy); err != nil {
		t.Fatal(err)
	}
	if emptyStrategy != (DestinationStrategy{}) {
		t.Fatalf("unexpected empty strategy: %#v", emptyStrategy)
	}

	var stringStrategy DestinationStrategy
	if err := json.Unmarshal([]byte(`"prefer_destination_addresses"`), &stringStrategy); err != nil {
		t.Fatal(err)
	}
	if stringStrategy.Strategy != C.DestinationStrategyPreferDestinationAddresses || stringStrategy.OverrideWithDomain != nil {
		t.Fatalf("unexpected string strategy: %#v", stringStrategy)
	}

	var evaluatedStrategy DestinationStrategy
	if err := json.Unmarshal([]byte(`{"strategy":"prefer_destination","override_with_domain":{"ip_only":true}}`), &evaluatedStrategy); err != nil {
		t.Fatal(err)
	}
	built := evaluatedStrategy.Build("default")
	if built.Strategy != C.DestinationStrategyPreferDestination || built.OverrideWithDomain == nil || built.OverrideWithDomain.Evaluator != "default" || !built.OverrideWithDomain.IPOnly {
		t.Fatalf("unexpected evaluated strategy: %#v", built)
	}
}

func TestDestinationStrategyRejectsInvalidJSON(t *testing.T) {
	for _, content := range []string{
		`"unknown"`,
		`{"strategy":"prefer_destination_addresses","override_with_domain":{}}`,
		`{"override_with_domain":{}}`,
		`{"strategy":"prefer_destination","override_with_domain":{"unknown":true}}`,
		`{}`,
		`{"strategy":"prefer_destination","unknown":true}`,
	} {
		var strategy DestinationStrategy
		if err := json.Unmarshal([]byte(content), &strategy); err == nil {
			t.Fatalf("expected %s to fail", content)
		}
	}
}
