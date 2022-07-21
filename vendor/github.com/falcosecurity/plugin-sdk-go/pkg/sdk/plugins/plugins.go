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

package plugins

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initschema"
)

// Info is a struct containing the general information about a plugin.
type Info struct {
	ID                  uint32
	Name                string
	Description         string
	EventSource         string
	Contact             string
	Version             string
	RequiredAPIVersion  string
	ExtractEventSources []string
}

// Plugin is an interface representing a plugin.
// Implementations of this interface can optionally implement the sdk.Destroy
// interface to specify a Destroy method will be called during the
// plugin deinitialization.
type Plugin interface {
	// (optional): sdk.Destroyer
	// (optional): sdk.InitSchema
	sdk.LastError
	sdk.LastErrorBuffer
	//
	// Info returns a pointer to a Info struct, containing
	// all the general information about this plugin.
	Info() *Info
	//
	// Init initializes this plugin with a given config string.
	// A successful call to init returns a nil error.
	Init(config string) error
}

// BaseEvents is a base implementation of the sdk.Events interface.
type BaseEvents struct {
	events sdk.EventWriters
}

func (b *BaseEvents) Events() sdk.EventWriters {
	return b.events
}

func (b *BaseEvents) SetEvents(events sdk.EventWriters) {
	b.events = events
}

// BaseExtractRequests is a base implementation of the sdk.ExtractRequests
// interface.
type BaseExtractRequests struct {
	extrReqPool sdk.ExtractRequestPool
}

func (b *BaseExtractRequests) ExtractRequests() sdk.ExtractRequestPool {
	return b.extrReqPool
}

func (b *BaseExtractRequests) SetExtractRequests(pool sdk.ExtractRequestPool) {
	b.extrReqPool = pool
}

// BaseLastError is a base implementation of the sdk.LastError interface.
type BaseLastError struct {
	lastErr    error
	lastErrBuf ptr.StringBuffer
}

func (b *BaseLastError) LastError() error {
	return b.lastErr
}

func (b *BaseLastError) SetLastError(err error) {
	b.lastErr = err
}

func (b *BaseLastError) LastErrorBuffer() sdk.StringBuffer {
	return &b.lastErrBuf
}

// BaseStringer is a base implementation of the sdk.StringerBuffer interface.
type BaseStringer struct {
	stringerBuf ptr.StringBuffer
}

func (b *BaseStringer) StringerBuffer() sdk.StringBuffer {
	return &b.stringerBuf
}

// BaseProgress is a base implementation of the sdk.ProgressBuffer interface.
type BaseProgress struct {
	progressBuf ptr.StringBuffer
}

func (b *BaseProgress) ProgressBuffer() sdk.StringBuffer {
	return &b.progressBuf
}

// BaseOpenParams is a base implementation of the sdk.OpenParamsBuffer interface.
type BaseOpenParams struct {
	openParamsBuf ptr.StringBuffer
}

func (b *BaseOpenParams) OpenParamsBuffer() sdk.StringBuffer {
	return &b.openParamsBuf
}

// BasePlugin is a base implementation of the Plugin interface.
// Developer-defined Plugin implementations should be composed with BasePlugin
// to have out-of-the-box compliance with all the required interfaces.
type BasePlugin struct {
	BaseLastError
	BaseStringer
	BaseExtractRequests
	BaseOpenParams
}

// FactoryFunc creates a new Plugin
type FactoryFunc func() Plugin

// SetFactory sets the FactoryFunc to be used by the SDK when creating a new Plugin
//
// SetFactory should be called in the Go init() function of the plugin main package.
// It hooks the plugin framework initialization stage to create a new Plugin and
// to set up common facilities provided by this SDK. The given FactoryFunc must create
// a Plugin and can optionally enable plugin capabilities by using the Register functions
// provided by sub-packages. This function is idempotent.
//
// Usage example:
//
//	package main
//
//	import (
//		"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
//		"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
//		"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
//	)
//
//	func init() {
//		plugins.SetFactory(func() plugins.Plugin {
//			p := &MyPlugin{} // create a new Plugin
//			source.Register(p) // enable event sourcing capability
//			extractor.Register(p) // enable field extraction capability
//			return p
//		})
//	}
//
func SetFactory(f FactoryFunc) {

	// Create a new plugin instance to get static plugin info
	p := f()

	// Set up plugin info
	i := p.Info()
	info.SetId(i.ID)
	info.SetName(i.Name)
	info.SetDescription(i.Description)
	info.SetEventSource(i.EventSource)
	info.SetExtractEventSources(i.ExtractEventSources)
	info.SetContact(i.Contact)
	info.SetVersion(i.Version)
	info.SetRequiredAPIVersion(i.RequiredAPIVersion)

	// Set up plugin init schema, if any
	if initSchema, ok := p.(sdk.InitSchema); ok {
		initschema.SetInitSchema(initSchema.InitSchema())
	}

	initialize.SetOnInit(func(c string) (sdk.PluginState, error) {
		// Create a new plugin instance
		p := f()
		err := p.Init(c)
		return p, err
	})
}
