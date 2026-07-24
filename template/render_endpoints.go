package template

import (
	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/sing-box/option"
)

func (t *Template) renderEndpoints(_ M.Metadata, options *option.Options) error {
	options.Endpoints = t.Endpoints
	return nil
}
