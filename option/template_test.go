package option

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestTemplateRejectsRemovedDestinationStrategies(t *testing.T) {
	for _, field := range []string{
		"destination_strategy",
		"destination_strategy_direct",
		"destination_strategy_endpoint",
	} {
		t.Run(field, func(t *testing.T) {
			var template Template
			err := json.UnmarshalContext(context.Background(), []byte(`{"`+field+`":""}`), &template)
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("expected removed field %q to be rejected, got %v", field, err)
			}
		})
	}
}
