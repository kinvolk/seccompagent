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

/*
#include "plugin_info.h"
*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

// ExtractRequest represents an high-level abstraction that wraps a pointer to
// a ss_plugin_extract_field C structure, providing methods for accessing its
// fields in a go-friently way.
type ExtractRequest interface {
	// FieldID returns id of the field, as of its index in the list of fields
	// returned by plugin_get_fields
	FieldID() uint64
	//
	// FieldType returns the type of the field for which the value extraction
	// is requested. For now, only sdk.ParamTypeUint64 and
	// sdk.ParamTypeCharBuf are supported.
	FieldType() uint32
	//
	// Field returns the name of the field for which the value extraction
	// is requested.
	Field() string
	//
	// Arg returns the argument passed for the requested field. An empty string
	// is returned if no argument is specified.
	Arg() string
	//
	// SetValue sets the extracted value for the requested field.
	//
	// The underlying type of v must be compatible with the field type
	// associated to this extract request (as the returned by FieldType()),
	// otherwise SetValue will panic.
	SetValue(v interface{})
	//
	// SetPtr sets a pointer to a ss_plugin_extract_field C structure to
	// be wrapped in this instance of ExtractRequest.
	SetPtr(unsafe.Pointer)
}

// ExtractRequestPool represents a pool of reusable ExtractRequest objects.
// Each ExtractRequest can be reused by calling its SetPtr method to wrap
// a new ss_plugin_extract_field C structure pointer.
type ExtractRequestPool interface {
	// Get returns an instance of ExtractRequest at the requestIndex
	// position inside the pool. Indexes can be non-contiguous.
	Get(requestIndex int) ExtractRequest
	//
	// Free deallocates any memory used by the pool that can't be disposed
	// through garbage collection. The behavior of Free after the first call
	// is undefined.
	Free()
}

type extractRequestPool struct {
	reqs map[uint]*extractRequest
}

func (e *extractRequestPool) Get(requestIndex int) ExtractRequest {
	r, ok := e.reqs[uint(requestIndex)]
	if !ok && requestIndex >= 0 {
		r = &extractRequest{
			strBuf: &ptr.StringBuffer{},
		}
		e.reqs[uint(requestIndex)] = r
	}
	return r
}

func (e *extractRequestPool) Free() {
	for _, v := range e.reqs {
		v.strBuf.Free()
	}
}

// NewExtractRequestPool returns a new empty ExtractRequestPool.
func NewExtractRequestPool() ExtractRequestPool {
	pool := &extractRequestPool{
		reqs: make(map[uint]*extractRequest),
	}
	return pool
}

type extractRequest struct {
	req    *C.ss_plugin_extract_field
	strBuf StringBuffer
}

func (e *extractRequest) SetPtr(pef unsafe.Pointer) {
	e.req = (*C.ss_plugin_extract_field)(pef)
}

func (e *extractRequest) FieldID() uint64 {
	return uint64(e.req.field_id)
}

func (e *extractRequest) FieldType() uint32 {
	return uint32(e.req.ftype)
}

func (e *extractRequest) Field() string {
	return ptr.GoString(unsafe.Pointer(e.req.field))
}

func (e *extractRequest) Arg() string {
	return ptr.GoString(unsafe.Pointer(e.req.arg))
}

func (e *extractRequest) SetValue(v interface{}) {
	switch e.FieldType() {
	case ParamTypeUint64:
		e.req.res_u64 = (C.uint64_t)(v.(uint64))
	case ParamTypeCharBuf:
		e.strBuf.Write(v.(string))
		e.req.res_str = (*C.char)(e.strBuf.CharPtr())
	default:
		panic("plugin-sdk-go/sdk: called SetValue with unsupported field type")
	}
	e.req.field_present = true
}
