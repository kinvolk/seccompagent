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
// - char* plugin_list_open_params()
//
// This function is part of the source_plugin_info and capture_plugin_info
// interfaces as defined in plugin_info.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package listopen

/*
#include <stdint.h>
*/
import "C"
import (
	"encoding/json"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_list_open_params
func plugin_list_open_params(pState C.uintptr_t, rc *int32) *C.char {
	*rc = sdk.SSPluginSuccess
	if openParams, ok := cgo.Handle(pState).Value().(sdk.OpenParams); ok {
		if buf, ok := cgo.Handle(pState).Value().(sdk.OpenParamsBuffer); ok {
			list, err := openParams.OpenParams()
			if err != nil {
				cgo.Handle(pState).Value().(sdk.LastError).SetLastError(err)
				*rc = sdk.SSPluginFailure
				return nil
			}
			b, err := json.Marshal(&list)
			if err != nil {
				cgo.Handle(pState).Value().(sdk.LastError).SetLastError(err)
				*rc = sdk.SSPluginFailure
				return nil
			}
			buf.OpenParamsBuffer().Write(string(b))
			return (*C.char)(buf.OpenParamsBuffer().CharPtr())
		}
	}
	return nil
}
