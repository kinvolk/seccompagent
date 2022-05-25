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
#include <stdlib.h>
#include <string.h>

// NOTE: This is just an replica of the anonymous union nested inside
// ss_plugin_extract_field. The only difference is that each union field has
// one pointer level less than its equivalent of ss_plugin_extract_field.
// Keep this in sync with plugin_info.h in case new types will be supported.
typedef union {
	const char* str;
	uint64_t u64;
} field_result_t;

*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

const (
	// Initial and minimum length with which the array of results is allocated
	// for a each extractRequest struct.
	minResultBufferLen = 512
)

// ExtractRequest represents an high-level abstraction that wraps a pointer to
// a ss_plugin_extract_field C structure, providing methods for accessing its
// fields in a go-friendly way.
type ExtractRequest interface {
	// FieldID returns id of the field, as of its index in the list of fields
	// returned by plugin_get_fields
	FieldID() uint64
	//
	// FieldType returns the type of the field for which the value extraction
	// is requested. For now, only sdk.FieldTypeUint64 and
	// sdk.FieldTypeCharBuf are supported.
	FieldType() uint32
	//
	// Field returns the name of the field for which the value extraction
	// is requested.
	Field() string
	//
	// ArgKey must be used when the field arg is a generic string (like a key
	// in a lookup operation). This field must have the `isKey` flag enabled.
	ArgKey() string
	//
	// ArgIndex must be used when the field arg is an index (0<=index<=2^64-1).
	// This field must have the `isIndex` flag enabled.
	ArgIndex() uint64
	//
	// ArgPresent clearly defines when an argument is valid or not.
	ArgPresent() bool
	//
	// IsList returns true if the field extracts lists of values.
	IsList() bool
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
			resBuf:     (*C.field_result_t)(C.malloc((C.size_t)(minResultBufferLen * C.sizeof_field_result_t))),
			resBufLen:  minResultBufferLen,
			resStrBufs: []StringBuffer{&ptr.StringBuffer{}},
		}
		e.reqs[uint(requestIndex)] = r
	}
	return r
}

func (e *extractRequestPool) Free() {
	for _, v := range e.reqs {
		for _, b := range v.resStrBufs {
			b.Free()
		}
		C.free(unsafe.Pointer(v.resBuf))
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
	req *C.ss_plugin_extract_field
	// Pointer to a C-allocated array of field_result_t
	resBuf *C.field_result_t
	// Length of the array pointed by resBuf
	resBufLen uint32
	// List of StringBuffer to return string results
	resStrBufs []StringBuffer
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

func (e *extractRequest) ArgKey() string {
	return ptr.GoString(unsafe.Pointer(e.req.arg_key))
}

func (e *extractRequest) ArgIndex() uint64 {
	return uint64(e.req.arg_index)
}

func (e *extractRequest) ArgPresent() bool {
	return bool(e.req.arg_present)
}

func (e *extractRequest) IsList() bool {
	return bool(e.req.flist)
}

func (e *extractRequest) SetValue(v interface{}) {
	switch e.FieldType() {
	case FieldTypeUint64:
		if e.req.flist {
			if e.resBufLen < uint32(len(v.([]uint64))) {
				C.free(unsafe.Pointer(e.resBuf))
				e.resBufLen = uint32(len(v.([]uint64)))
				e.resBuf = (*C.field_result_t)(C.malloc((C.size_t)(e.resBufLen * C.sizeof_field_result_t)))
			}
			for i, val := range v.([]uint64) {
				*((*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(e.resBuf)) + uintptr(i*C.sizeof_field_result_t)))) = (C.uint64_t)(val)
			}
			e.req.res_len = (C.uint64_t)(len(v.([]uint64)))
		} else {
			*((*C.uint64_t)(unsafe.Pointer(e.resBuf))) = (C.uint64_t)(v.(uint64))
			e.req.res_len = (C.uint64_t)(1)
		}
	case FieldTypeCharBuf:
		if e.req.flist {
			if e.resBufLen < uint32(len(v.([]string))) {
				C.free(unsafe.Pointer(e.resBuf))
				e.resBufLen = uint32(len(v.([]string)))
				e.resBuf = (*C.field_result_t)(C.malloc((C.size_t)(e.resBufLen * C.sizeof_field_result_t)))
			}
			for i, val := range v.([]string) {
				if len(e.resStrBufs) <= i {
					e.resStrBufs = append(e.resStrBufs, &ptr.StringBuffer{})
				}
				e.resStrBufs[i].Write(val)
				*((**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(e.resBuf)) + uintptr(i*C.sizeof_field_result_t)))) = (*C.char)(e.resStrBufs[i].CharPtr())
			}
			e.req.res_len = (C.uint64_t)(len(v.([]string)))
		} else {
			e.resStrBufs[0].Write(v.(string))
			*((**C.char)(unsafe.Pointer(e.resBuf))) = (*C.char)(e.resStrBufs[0].CharPtr())
			e.req.res_len = (C.uint64_t)(1)
		}
	default:
		panic("plugin-sdk-go/sdk: called SetValue with unsupported field type")
	}
	*((*C.uintptr_t)(unsafe.Pointer(&e.req.res))) = *(*C.uintptr_t)(unsafe.Pointer(&e.resBuf))
}
