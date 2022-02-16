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

package plugins

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
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
