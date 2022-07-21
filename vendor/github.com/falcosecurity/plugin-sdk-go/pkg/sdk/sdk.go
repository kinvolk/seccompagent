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

import (
	"errors"
)

// ErrEOF is the error returned by next_batch when no new events
// are available.
var ErrEOF = errors.New("eof")

// ErrTimeout is the error returned by next_batch when no new events
// are available for the current batch, but may be available in the
// next one.
var ErrTimeout = errors.New("timeout")

// Functions that return or update a rc (e.g. plugin_init,
// plugin_open) should return one of these values.
const (
	SSPluginSuccess      int32 = 0
	SSPluginFailure      int32 = 1
	SSPluginTimeout      int32 = -1
	SSPluginEOF          int32 = 2
	SSPluginNotSupported int32 = 3
)

// DefaultEvtSize is the default size for the data payload allocated
// for each event in the EventWriters interface used by the SDK.
const DefaultEvtSize uint32 = 256 * 1024

// DefaultBatchSize is the default number of events in the EventWriters
// interface used by the SDK.
const DefaultBatchSize = 128

// The full set of values that can be returned in the ftype
// member of ss_plugin_extract_field structs.
const (
	FieldTypeUint64  uint32 = 8
	FieldTypeCharBuf uint32 = 9 // A printable buffer of bytes, NULL terminated
)

// FieldEntry represents a single field entry that a plugin with field extraction
// capability can expose.
// Should be used when implementing plugin_get_fields().
type FieldEntry struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	IsList     bool          `json:"isList"`
	Arg        FieldEntryArg `json:"arg"`
	Display    string        `json:"display"`
	Desc       string        `json:"desc"`
	Properties []string      `json:"properties"`
}

// FieldEntryArg describes the argument of a single field entry that
// an plugin with field extraction capability can expose.
// Should be used when implementing plugin_get_fields().
type FieldEntryArg struct {
	IsRequired bool `json:"isRequired"`
	IsIndex    bool `json:"isIndex"`
	IsKey      bool `json:"isKey"`
}

// OpenParam represents a valid parameter for plugin_open().
type OpenParam struct {
	Value     string `json:"value"`
	Desc      string `json:"desc"`
	Separator string `json:"separator"`
}

// SchemaInfo represent a schema describing a structured data type.
// Should be used when implementing plugin_get_init_schema().
type SchemaInfo struct {
	Schema string
}
