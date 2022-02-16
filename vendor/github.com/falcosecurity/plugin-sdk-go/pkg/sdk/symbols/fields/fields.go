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
// - char* plugin_get_fields()
//
// This function is part of the source_plugin_info and extractor_plugin_info
// interfaces as defined in plugin_info.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package fields

import "C"
import (
	"encoding/json"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var (
	fields []sdk.FieldEntry
	buf    ptr.StringBuffer
)

// SetFields sets a slice of sdk.FieldEntry representing the list of extractor
// fields exported by this plugin.
func SetFields(f []sdk.FieldEntry) {
	fields = f
}

// Fields returns the slice of sdk.FieldEntry set with SetFields().
func Fields() []sdk.FieldEntry {
	return fields
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	b, err := json.Marshal(&fields)
	if err != nil {
		return nil
	}
	buf.Write(string(b))
	return (*C.char)(buf.CharPtr())
}
