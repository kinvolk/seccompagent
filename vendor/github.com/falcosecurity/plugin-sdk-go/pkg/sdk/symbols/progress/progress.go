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
// - char* plugin_get_progress(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct)
//
// The exported plugin_get_progress requires that both s and h are handles
// of cgo.Handle from this SDK. The value of the s handle must implement
// the sdk.PluginState interface. The value of the h handle must implement
// the sdk.Progresser and sdk.ProgressBuffer interfaces.
//
// This function is part of the source_plugin_info interface as defined in
// plugin_info.h. In almost all cases, your plugin should import this module,
// unless your plugin exports those symbols by other means.
package progress

/*
#include <stdint.h>
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_get_progress
func plugin_get_progress(pState C.uintptr_t, iState C.uintptr_t, progress_pct *uint32) *C.char {
	buf := cgo.Handle(iState).Value().(sdk.ProgressBuffer).ProgressBuffer()
	progresser, ok := cgo.Handle(iState).Value().(sdk.Progresser)
	if ok {
		pct, str := progresser.Progress(cgo.Handle(pState).Value().(sdk.PluginState))
		*progress_pct = uint32(pct * 10000)
		buf.Write(str)
		return (*C.char)(buf.CharPtr())
	}
	*progress_pct = 0
	return (*C.char)(nil)
}
