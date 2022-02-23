/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package extractor provides high-level constructs to easily build
// extractor plugins.
package extractor

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/internal/hooks"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/fields"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initschema"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
)

var registered = false

// Plugin is an interface representing an extractor plugin.
type Plugin interface {
	plugins.Plugin
	sdk.Extractor
	sdk.ExtractRequests
	//
	// Fields return the list of extractor fields exported by this plugin.
	Fields() []sdk.FieldEntry
}

// Register registers a Plugin extractor plugin in the framework. This function
// needs to be called in a Go init() function. Calling this function more than
// once will cause a panic.
//
// Register can also be called to register source plugins with optional
// extraction capabilities. If this function is called before, or after, having
// registered a source plugin in the SDK, the registered plugin will be a
// plugin of type sdk.TypeSourcePlugin with extraction capabilities enabled.
func Register(p Plugin) {
	if registered {
		panic("plugin-sdk-go/sdk/plugins/extractor: register can be called only once")
	}

	// Currently TypeExtractorPlugin is also compatible with source plugins
	// that export extract-related symbols.
	switch info.Type() {
	case 0:
		info.SetType(sdk.TypeExtractorPlugin)
	case sdk.TypeExtractorPlugin:
	case sdk.TypeSourcePlugin: // source plugins have the priority over extractor plugins
		break
	default:
		panic("plugin-sdk-go/sdk/plugins/extractor: unsupported type has already been set")
	}
	i := p.Info()
	info.SetId(i.ID)
	info.SetName(i.Name)
	info.SetDescription(i.Description)
	info.SetEventSource(i.EventSource)
	info.SetContact(i.Contact)
	info.SetVersion(i.Version)
	info.SetRequiredAPIVersion(i.RequiredAPIVersion)
	info.SetExtractEventSources(i.ExtractEventSources)
	if initSchema, ok := p.(sdk.InitSchema); ok {
		initschema.SetInitSchema(initSchema.InitSchema())
	}

	fields.SetFields(p.Fields())

	initialize.SetOnInit(func(c string) (sdk.PluginState, error) {
		err := p.Init(c)
		return p, err
	})

	// setup hooks for automatically start/stop async extraction
	hooks.SetOnAfterInit(func(handle cgo.Handle) {
		extract.StartAsync()
		hooks.SetOnBeforeDestroy(func(handle cgo.Handle) {
			extract.StopAsync()
		})
	})

	registered = true
}
