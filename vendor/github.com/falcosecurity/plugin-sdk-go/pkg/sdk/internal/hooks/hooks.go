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

// Package hooks contains a set of hooks to be used internally in the SDK.
package hooks

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
)

type OnBeforeDestroyFn func(handle cgo.Handle)
type OnAfterInitFn func(handle cgo.Handle)

var (
	onBeforeDestroy OnBeforeDestroyFn = func(cgo.Handle) {}
	onAfterInit     OnAfterInitFn     = func(cgo.Handle) {}
)

// SetOnBeforeDestroy sets a callback that is invoked before the Destroy() method.
func SetOnBeforeDestroy(fn OnBeforeDestroyFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/initialize.SetOnBeforeDestroy: fn must not be nil")
	}
	onBeforeDestroy = fn
}

// OnBeforeDestroy returns a callback that is invoked before the Destroy() method.
func OnBeforeDestroy() OnBeforeDestroyFn {
	return onBeforeDestroy
}

// SetOnAfterInit sets a callback that is invoked after the Init() method.
func SetOnAfterInit(fn OnAfterInitFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/initialize.SetOnAfterInit: fn must not be nil")
	}
	onAfterInit = fn
}

// OnAfterInit returns a callback that is invoked after the Init() method.
func OnAfterInit() OnAfterInitFn {
	return onAfterInit
}
