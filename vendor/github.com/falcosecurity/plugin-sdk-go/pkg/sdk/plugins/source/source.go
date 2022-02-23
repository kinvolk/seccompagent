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

// Package source provides high-level constructs to easily build
// source plugins.
package source

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/evtstr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initschema"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/listopen"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/nextbatch"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/open"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/progress"
)

var registered = false

// Plugin is an interface representing a source plugin.
type Plugin interface {
	plugins.Plugin
	sdk.Stringer
	sdk.StringerBuffer
	sdk.OpenParamsBuffer
	// (optional) sdk.OpenParams

	//
	// Open opens the source and starts a capture (e.g. stream of events).
	//
	// The argument string represents the user-defined parameters and
	// can be used to customize how the source is opened.
	// The return value is an Instance representing the source capture session.
	// There can be multiple instances of the same source open.
	// A successfull call to Open returns a nil error.
	//
	// The sdk.EventWriters event buffer, that is reused during each cycle
	// of new event creation, is initialized in automatic after the execution
	// of Open with the SetEvents method of the Instance interface.
	// Developers may override the default sdk.EventWriters by setting it
	// on the returned Instance with SetEvents, before returning from Open.
	// This can help specifying the data event size, the size of each
	// event batch, or just to use an implementation of the
	// sdk.EventWriters interface different from the SDK default one.
	Open(params string) (Instance, error)
}

// Instance is an interface representing a source capture session instance
// returned by a call to Open of a source plugin.
//
// Implementations of this interface must implement sdk.NextBatcher, and can
// optionally implement sdk.Closer and sdk.Progresser.
// If sdk.Closer is implemented, the Close method will be called while closing
// the source capture session.
type Instance interface {
	// (optional) sdk.Closer
	// (optional) sdk.Progresser
	sdk.Events
	sdk.NextBatcher
	sdk.ProgressBuffer
}

// BaseInstance is a base implementation of the Instance interface.
// Developer-defined Instance implementations should be composed with BaseInstance
// to have out-of-the-box compliance with all the required interfaces.
type BaseInstance struct {
	plugins.BaseEvents
	plugins.BaseProgress
}

// Register registers a Plugin source plugin in the framework. This function
// needs to be called in a Go init() function. Calling this function more than
// once will cause a panic.
//
// Register registers a source plugin in the SDK. In order to
// register a source plugin with optional extraction capabilities, the
// extractor.Register function must be called by passing the same Plugin
// argument. In this case, the order in which Register and extractor.Register
// are called in the init() function is not relevant. This is needed for the
// framework to notice that the source plugin implements the extraction-related
// methods.
func Register(p Plugin) {
	if registered {
		panic("plugin-sdk-go/sdk/plugins/source: register can be called only once")
	}

	i := p.Info()
	info.SetType(sdk.TypeSourcePlugin)
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

	initialize.SetOnInit(func(c string) (sdk.PluginState, error) {
		err := p.Init(c)
		return p, err
	})

	open.SetOnOpen(func(c string) (sdk.InstanceState, error) {
		return p.Open(c)
	})

	registered = true
}
