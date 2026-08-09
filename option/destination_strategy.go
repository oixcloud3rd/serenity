package option

import (
	"bytes"
	stdjson "encoding/json"

	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type DestinationStrategy struct {
	Strategy           string
	OverrideWithDomain *OverrideWithDomainOptions
}

// OverrideWithDomainOptions omits the evaluator tag exposed by sing-box.
// Serenity generates and references a single evaluator automatically.
type OverrideWithDomainOptions struct {
	IPOnly bool `json:"ip_only,omitempty"`
}

type rawDestinationStrategy struct {
	Strategy           string                     `json:"strategy"`
	OverrideWithDomain *OverrideWithDomainOptions `json:"override_with_domain,omitempty"`
}

func (s DestinationStrategy) MarshalJSON() ([]byte, error) {
	if s.OverrideWithDomain == nil {
		return json.Marshal(s.Strategy)
	}
	return json.Marshal(rawDestinationStrategy(s))
}

func (s *DestinationStrategy) UnmarshalJSON(content []byte) error {
	var strategy string
	if err := json.Unmarshal(content, &strategy); err == nil {
		if strategy == "" {
			*s = DestinationStrategy{}
			return nil
		}
		if err = validateDestinationStrategy(strategy, nil); err != nil {
			return err
		}
		s.Strategy = strategy
		s.OverrideWithDomain = nil
		return nil
	}
	var raw rawDestinationStrategy
	decoder := stdjson.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if raw.Strategy == "" {
		return E.New("missing destination strategy")
	}
	if err := validateDestinationStrategy(raw.Strategy, raw.OverrideWithDomain); err != nil {
		return err
	}
	*s = DestinationStrategy(raw)
	return nil
}

func validateDestinationStrategy(strategy string, overrideWithDomain *OverrideWithDomainOptions) error {
	switch strategy {
	case C.DestinationStrategyPreferDestinationAddresses:
		if overrideWithDomain != nil {
			return E.New("override_with_domain is only available with prefer_destination")
		}
	case C.DestinationStrategyPreferDestination:
	default:
		return E.New("unknown destination strategy: ", strategy)
	}
	return nil
}

func (s DestinationStrategy) Build(evaluator string) *boxOption.DestinationStrategy {
	strategy := &boxOption.DestinationStrategy{Strategy: s.Strategy}
	if s.OverrideWithDomain != nil {
		strategy.OverrideWithDomain = &boxOption.OverrideWithDomainOptions{
			Evaluator: evaluator,
			IPOnly:    s.OverrideWithDomain.IPOnly,
		}
	}
	return strategy
}
