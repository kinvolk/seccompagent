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

// This package exports the following C function:
// - ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts)
//
// The exported plugin_next_batch requires s and h to be a handles
// of cgo.Handle from this SDK. The value of the s handle must implement
// the sdk.PluginState interface. The value of the h handle must implement
// the sdk.Events and the sdk.NextBatcher interfaces.
//
// This function is part of the source_plugin_info interface as defined in
// plugin_info.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package nextbatch

/*
#include "../../plugin_info.h"
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_next_batch
func plugin_next_batch(pState C.uintptr_t, iState C.uintptr_t, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
	events := cgo.Handle(iState).Value().(sdk.Events).Events()
	n, err := cgo.Handle(iState).Value().(sdk.NextBatcher).NextBatch(cgo.Handle(pState).Value().(sdk.PluginState), events)

	*nevts = uint32(n)
	*retEvts = (*C.ss_plugin_event)(events.ArrayPtr())
	switch err {
	case nil:
		return sdk.SSPluginSuccess
	case sdk.ErrEOF:
		return sdk.SSPluginEOF
	case sdk.ErrTimeout:
		return sdk.SSPluginTimeout
	default:
		*nevts = uint32(0)
		*retEvts = nil
		cgo.Handle(pState).Value().(sdk.LastError).SetLastError(err)
		return sdk.SSPluginFailure
	}
}
