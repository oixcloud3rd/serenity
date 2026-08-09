package template

import (
	"reflect"

	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
)

var destinationStrategyVersion = semver.ParseVersion("1.14.0-beta.12")

func (t *Template) renderDestinationStrategies(metadata M.Metadata, options *boxOption.Options) {
	detachDestinationStrategyOptions(options)
	if metadata.Version != nil && metadata.Version.LessThan(destinationStrategyVersion) {
		clearDestinationStrategies(options)
		return
	}

	directTag := t.DirectTag
	if directTag == "" {
		directTag = DefaultDirectTag
	}
	for index := range options.Outbounds {
		outbound := &options.Outbounds[index]
		if outbound.Type == C.TypeSelector || outbound.Type == C.TypeURLTest {
			continue
		}
		strategy := t.DestinationStrategy
		if outbound.Tag == directTag {
			strategy = t.DestinationStrategyDirect
		}
		applyDestinationStrategy(outbound.Options, strategy)
	}
	for index := range options.Endpoints {
		applyDestinationStrategy(options.Endpoints[index].Options, t.DestinationStrategyEndpoint)
	}

	evaluationEnabled := false
	visitDestinationStrategies(options, func(strategy *boxOption.DestinationStrategy) {
		if strategy.OverrideWithDomain == nil {
			return
		}
		strategy.OverrideWithDomain.Evaluator = DefaultDomainEvaluatorTag
		evaluationEnabled = true
	})
	if evaluationEnabled {
		options.DomainEvaluators = []boxOption.DomainEvaluatorOptions{{Tag: DefaultDomainEvaluatorTag}}
	} else {
		options.DomainEvaluators = nil
	}
}

func detachDestinationStrategyOptions(options *boxOption.Options) {
	for index := range options.Outbounds {
		options.Outbounds[index].Options = cloneDestinationStrategyOptions(options.Outbounds[index].Options)
	}
	for index := range options.Endpoints {
		options.Endpoints[index].Options = cloneDestinationStrategyOptions(options.Endpoints[index].Options)
	}
}

func cloneDestinationStrategyOptions(options any) any {
	wrapper, loaded := options.(boxOption.DestinationStrategyOptionsWrapper)
	if !loaded {
		return options
	}
	value := reflect.ValueOf(options)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return options
	}
	clonedValue := reflect.New(value.Elem().Type())
	clonedValue.Elem().Set(value.Elem())
	clonedOptions := clonedValue.Interface()
	if strategy := wrapper.TakeDestinationStrategy(); strategy != nil {
		clonedStrategy := *strategy
		if strategy.OverrideWithDomain != nil {
			clonedOverride := *strategy.OverrideWithDomain
			clonedStrategy.OverrideWithDomain = &clonedOverride
		}
		setDestinationStrategy(clonedOptions, &clonedStrategy)
	}
	return clonedOptions
}

func clearDestinationStrategies(options *boxOption.Options) {
	for index := range options.Outbounds {
		setDestinationStrategy(options.Outbounds[index].Options, nil)
	}
	for index := range options.Endpoints {
		setDestinationStrategy(options.Endpoints[index].Options, nil)
	}
	options.DomainEvaluators = nil
}

func applyDestinationStrategy(options any, strategy *serenityOption.DestinationStrategy) {
	if strategy == nil || strategy.Strategy == "" {
		return
	}
	setDestinationStrategy(options, strategy.Build(DefaultDomainEvaluatorTag))
}

func visitDestinationStrategies(options *boxOption.Options, visit func(*boxOption.DestinationStrategy)) {
	for index := range options.Outbounds {
		if wrapper, loaded := options.Outbounds[index].Options.(boxOption.DestinationStrategyOptionsWrapper); loaded {
			if strategy := wrapper.TakeDestinationStrategy(); strategy != nil {
				visit(strategy)
			}
		}
	}
	for index := range options.Endpoints {
		if wrapper, loaded := options.Endpoints[index].Options.(boxOption.DestinationStrategyOptionsWrapper); loaded {
			if strategy := wrapper.TakeDestinationStrategy(); strategy != nil {
				visit(strategy)
			}
		}
	}
}

func setDestinationStrategy(options any, strategy *boxOption.DestinationStrategy) bool {
	if _, loaded := options.(boxOption.DestinationStrategyOptionsWrapper); !loaded {
		return false
	}
	value := reflect.ValueOf(options)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return false
	}
	value = value.Elem()
	strategyOptions := value.FieldByName("DestinationStrategyOptions")
	if !strategyOptions.IsValid() {
		return false
	}
	strategyField := strategyOptions.FieldByName("DestinationStrategy")
	if !strategyField.IsValid() || !strategyField.CanSet() {
		return false
	}
	strategyField.Set(reflect.ValueOf(strategy))
	return true
}
