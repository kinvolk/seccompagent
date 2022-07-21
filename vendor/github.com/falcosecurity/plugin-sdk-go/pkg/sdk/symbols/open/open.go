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

// This package exports the following C functions:
// - ss_instance_t* plugin_open(ss_plugin_t* s, char* params, ss_plugin_rc* rc)
// - void plugin_close(ss_plugin_t* s, ss_instance_t* h)
//
// The exported plugin_open requires s to be a handle
// of cgo.Handle from this SDK. The value of the s handle must implement
// the sdk.LastError interface. plugin_open calls the function set with
// SetOnOpen, which returns a sdk.InstanceState interface. If the return
// value implements the sdk.Events interface, the function checks if an
// instance of sdk.EventWriters has already been set. If not, a default
// one is created on the fly and set with the SetEvents method.
//
// The exported plugin_close requires h to be a handle
// of cgo.Handle from this SDK. If the value of the h handle implements
// the sdk.Closer interface, the function calls its Close method.
// If sdk.Events is implemented the function calls the Free method
// on the returned sdk.EventWriters. Finally, the function deletes the
// h cgo.Handle.
//
// This function is part of the source_plugin_info interface as defined
// in plugin_info.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package open

/*
#include <stdint.h>
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var (
	onOpenFn OnOpenFn
)

// OnOpenFn is a callback used in plugin_open.
type OnOpenFn func(config string) (sdk.InstanceState, error)

// SetOnInit sets an initialization callback to be called in plugin_open to
// create the plugin instance state. If never set, plugin_open will panic.
func SetOnOpen(fn OnOpenFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/open.SetOnOpen: fn must not be nil")
	}
	onOpenFn = fn
}

//export plugin_open
func plugin_open(plgState C.uintptr_t, params *C.char, rc *int32) C.uintptr_t {
	if onOpenFn == nil {
		panic("plugin-sdk-go/sdk/symbols/open: SetOnOpen must be called")
	}

	iState, err := onOpenFn(C.GoString(params))
	if err == nil {
		// this allows a nil iState
		iEvents, ok := iState.(sdk.Events)
		if ok && iEvents.Events() == nil {
			var events sdk.EventWriters
			events, err = sdk.NewEventWriters(int64(sdk.DefaultBatchSize), int64(sdk.DefaultEvtSize))
			if err == nil {
				iEvents.SetEvents(events)
			}
		}
	}

	if err != nil {
		cgo.Handle(plgState).Value().(sdk.LastError).SetLastError(err)
		*rc = sdk.SSPluginFailure
		return 0
	}
	*rc = sdk.SSPluginSuccess
	return (C.uintptr_t)(cgo.NewHandle(iState))
}

//export plugin_close
func plugin_close(plgState C.uintptr_t, instanceState C.uintptr_t) {
	if instanceState != 0 {
		handle := cgo.Handle(instanceState)
		if state, ok := handle.Value().(sdk.Closer); ok {
			state.Close()
		}
		if state, ok := handle.Value().(sdk.Events); ok {
			state.Events().Free()
			state.SetEvents(nil)
		}
		handle.Delete()
	}
}
