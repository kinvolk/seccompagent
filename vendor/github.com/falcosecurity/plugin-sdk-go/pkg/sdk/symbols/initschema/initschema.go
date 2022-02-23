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
// - const char* get_init_schema(ss_plugin_schema_type* schema_type)
//
// This function is part of the source_plugin_info and extractor_plugin_info
// interfaces as defined in plugin_info.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package initschema

/*
#include "../../plugin_info.h"
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var (
	schema *sdk.SchemaInfo
	buf    ptr.StringBuffer
)

// SetInitSchema sets a pointer to sdk.SchemaInfo representing the schema
// of the configuration expected by the plugin during initialization.
func SetInitSchema(s *sdk.SchemaInfo) {
	schema = s
}

// InitSchema returns the pointer to sdk.SchemaInfo set with SetInitSchema().
func InitSchema() *sdk.SchemaInfo {
	return schema
}

//export plugin_get_init_schema
func plugin_get_init_schema(schema_type *C.ss_plugin_schema_type) *C.char {
	str := ""
	*schema_type = C.SS_PLUGIN_SCHEMA_NONE
	if schema != nil {
		str = schema.Schema
		*schema_type = C.SS_PLUGIN_SCHEMA_JSON
	}
	buf.Write(str)
	return (*C.char)(buf.CharPtr())
}
