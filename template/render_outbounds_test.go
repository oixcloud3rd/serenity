package template

import (
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
)

func TestDisablePreconnect(t *testing.T) {
	testCases := []struct {
		name       string
		disabled   bool
		platform   M.Platform
		preconnect int
	}{
		{
			name:       "iOS",
			disabled:   true,
			platform:   M.PlatformiOS,
			preconnect: 0,
		},
		{
			name:       "tvOS",
			disabled:   true,
			platform:   M.PlatformAppleTVOS,
			preconnect: 0,
		},
		{
			name:       "macOS",
			disabled:   true,
			platform:   M.PlatformMacOS,
			preconnect: 2,
		},
		{
			name:       "Android",
			disabled:   true,
			platform:   M.PlatformAndroid,
			preconnect: 2,
		},
		{
			name:       "disabled option",
			disabled:   false,
			platform:   M.PlatformiOS,
			preconnect: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sourceOptions := &boxOption.SnellOutboundOptions{
				AbstractSnellOutboundOptions: boxOption.AbstractSnellOutboundOptions{
					Preconnect: 2,
				},
			}
			template := &Template{
				Template: serenityOption.Template{
					DisablePreconnect: testCase.disabled,
				},
			}
			options := boxOption.Options{Route: &boxOption.RouteOptions{}}
			err := template.renderOutbounds(M.Metadata{Platform: testCase.platform}, &options, [][]boxOption.Outbound{{
				{
					Type:    C.TypeSnell,
					Tag:     "snell",
					Options: sourceOptions,
				},
			}}, nil)
			if err != nil {
				t.Fatal(err)
			}

			renderedOptions, ok := options.Outbounds[2].Options.(*boxOption.SnellOutboundOptions)
			if !ok {
				t.Fatalf("unexpected outbound options: %T", options.Outbounds[2].Options)
			}
			if renderedOptions.Preconnect != testCase.preconnect {
				t.Fatalf("unexpected preconnect: got %d, want %d", renderedOptions.Preconnect, testCase.preconnect)
			}
			if sourceOptions.Preconnect != 2 {
				t.Fatalf("source outbound was mutated: preconnect=%d", sourceOptions.Preconnect)
			}
		})
	}
}
