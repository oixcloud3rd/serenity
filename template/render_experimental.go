package template

import (
	"context"

	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	boxConstant "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badjson"
)

func (t *Template) renderExperimental(ctx context.Context, metadata M.Metadata, options *option.Options, profileName string) error {
	if t.DisableCacheFile && t.DisableClashMode && t.CustomClashAPI == nil {
		return nil
	}
	options.Experimental = &option.ExperimentalOptions{}
	if !t.DisableCacheFile {
		options.Experimental.CacheFile = &option.CacheFileOptions{
			Enabled:     true,
			CacheID:     profileName,
			StoreFakeIP: t.EnableFakeIP,
		}
		if !t.DisableDNSLeak {
			if metadata.Version == nil || metadata.Version.GreaterThanOrEqual(semver.ParseVersion("1.14.0-alpha.1")) {
				options.Experimental.CacheFile.StoreDNS = true
			} else {
				options.Experimental.CacheFile.StoreRDRC = true
			}
		}
	}

	if t.CustomClashAPI != nil {
		newClashOptions, err := badjson.MergeFromDestination(ctx, options.Experimental.ClashAPI, t.CustomClashAPI.Message, true)
		if err != nil {
			return err
		}
		options.Experimental.ClashAPI = newClashOptions
	} else if options.Experimental.ClashAPI == nil {
		options.Experimental.ClashAPI = &option.ClashAPIOptions{}
	}

	if !t.DisableExternalController && options.Experimental.ClashAPI.ExternalController == "" {
		options.Experimental.ClashAPI.ExternalController = "127.0.0.1:9090"
	}

	if !t.DisableClashMode {
		if !t.DisableDNSLeak {
			clashModeLeak := t.ClashModeLeak
			if clashModeLeak == "" {
				clashModeLeak = "Leak"
			}
			options.Experimental.ClashAPI.DefaultMode = clashModeLeak
		} else {
			options.Experimental.ClashAPI.DefaultMode = t.ClashModeRule
		}
	}
	if t.PProfListen != "" {
		if options.Experimental.Debug == nil {
			options.Experimental.Debug = &option.DebugOptions{}
		}
		options.Experimental.Debug.Listen = t.PProfListen
	}
	if t.MemoryLimit.Value() > 0 && metadata.Platform.IsNetworkExtensionMemoryLimited() {
		oomKillerService := metadata.Version == nil || metadata.Version.GreaterThanOrEqual(semver.ParseVersion("1.13.0-rc.7"))
		if oomKillerService {
			options.Services = append(options.Services, option.Service{
				Type: boxConstant.TypeOOMKiller,
				Options: option.OOMKillerServiceOptions{
					MemoryLimit: t.MemoryLimit,
				},
			})
		} else {
			if options.Experimental.Debug == nil {
				options.Experimental.Debug = &option.DebugOptions{}
			}
			options.Experimental.Debug.MemoryLimit = t.MemoryLimit
			options.Experimental.Debug.OOMKiller = common.Ptr(true)
		}
	}
	return nil
}
