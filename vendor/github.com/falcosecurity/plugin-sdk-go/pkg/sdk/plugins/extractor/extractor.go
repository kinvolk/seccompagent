/*
Copyright (C) 2022 The Falco Authors.

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
// plugins with field extraction capability.
package extractor

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/internal/hooks"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/fields"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
)

// Plugin is an interface representing a plugin with field extraction capability.
type Plugin interface {
	plugins.Plugin
	sdk.Extractor
	sdk.ExtractRequests
	//
	// Fields return the list of extractor fields exported by this plugin.
	Fields() []sdk.FieldEntry
}

func enableAsync(handle cgo.Handle) {
	extract.StartAsync()
	hooks.SetOnBeforeDestroy(func(handle cgo.Handle) {
		extract.StopAsync()
	})
}

// Register registers the field extraction capability in the framework for the given Plugin.
//
// This function should be called from the provided plugins.FactoryFunc implementation.
// See the parent package for more detail. This function is idempotent.
func Register(p Plugin) {

	fields.SetFields(p.Fields())

	// setup hooks for automatically start/stop async extraction
	hooks.SetOnAfterInit(enableAsync)
}
