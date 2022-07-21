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

package sdk

// PluginState represents the state of a plugin returned by plugin_init().
type PluginState interface {
}

type ExtractRequests interface {
	ExtractRequests() ExtractRequestPool
	SetExtractRequests(ExtractRequestPool)
}

// LastError is a compasable interface wrapping the basic LastError and
// SetLastError methods. This is meant to be used as a standard
// container for the last error catched during the execution of a plugin.
type LastError interface {
	// LastError returns the last error occurred in the plugin.
	LastError() error
	//
	// SetLastError sets the last error occurred in the plugin.
	SetLastError(err error)
}

// Destroyer is an interface wrapping the basic Destroy method.
// Destroy deinitializes the resources opened or allocated by a plugin.
// This is meant to be used in plugin_destroy() to release the plugin's
// resources. The behavior of Destroy after the first call is undefined.
type Destroyer interface {
	Destroy()
}

// Stringer is an interface wrapping the basic String method.
// String takes an EventReader and produces a string representation
// describing its internal data. This is meant to be used in
// plugin_event_to_string(), where the event is provided by the framework
// and previouly produced by an invocation of plugin_next_batch() of this
// plugin.
type Stringer interface {
	String(evt EventReader) (string, error)
}

// Extractor is an interface wrapping the basic Extract method.
// Extract is meant to be used in plugin_extract_fields() to extract the value
// of a single field from a given event data.
type Extractor interface {
	Extract(req ExtractRequest, evt EventReader) error
}

// OpenParams is an interface wrapping the basic OpenParams method.
// OpenParams is meant to be used in plugin_list_open_params() to return a list
// of suggested parameters that would be accepted as valid arguments
// for plugin_open().
type OpenParams interface {
	OpenParams() ([]OpenParam, error)
}

// InitSchema is an interface wrapping the basic InitSchema method.
// InitSchema is meant to be used in plugin_get_init_schema() to return a
// schema describing the data expected to be passed as a configuration
// during the plugin initialization. The schema must follow the JSON Schema
// specific: https://json-schema.org/. A nil return value is interpreted
// as the absence of a schema, and the init configuration will not be
// pre-validated by the framework. If JSON Schema is returned, the
// init configuration will be expected to be a json-formatted string.
// If so, the init() function can assume the configuration to be well-formed
// according to the returned schema, as the framework will perform a
// pre-validation before initializing the plugin.
type InitSchema interface {
	InitSchema() *SchemaInfo
}
