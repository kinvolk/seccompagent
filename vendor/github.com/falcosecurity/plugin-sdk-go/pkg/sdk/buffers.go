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

import "unsafe"

// StringBuffer represents a buffer for C-allocated null-terminated strings
// in a Go-friendly way. Unlike the C.CString function, this interface helps
// convert a Go string in a C-like one by always reusing the same buffer.
// Implementations of this interface must take care of allocating the
// underlying C buffer.
type StringBuffer interface {
	// Write writes a Go string inside the buffer, converting it to a C-like
	// null-terminated string. Implementations of this interface must handle
	// the case in which the buffer is not large enough to host the converted
	// string.
	Write(string)
	//
	// String returns a Go string obtained by converting the C-like string
	// currently stored in the buffer. If the buffer is empty, an empty string
	// is returned.
	String() string
	//
	// CharPtr returns an unsafe pointer to the underlying C-allocated
	// char* buffer. Freeing the returned pointer by any sort of deallocator
	// (C.free or similars) can lead to undefined behavior.
	CharPtr() unsafe.Pointer
	//
	// Free deallocates the underlying C-allocated buffer. The behavior of Free
	// after the first call is undefined.
	Free()
}

// LastErrorBuffer is an interface wrapping the basic LastErrorBuffer method.
// LastErrorBuffer returns a StringBuffer meant to be used as buffer for
// plugin_get_last_error().
type LastErrorBuffer interface {
	LastErrorBuffer() StringBuffer
}

// StringerBuffer is an interface wrapping the basic StringerBuffer method.
// StringerBuffer returns a StringBuffer meant to be used as buffer for
// plugin_event_to_string().
type StringerBuffer interface {
	StringerBuffer() StringBuffer
}

// ProgressBuffer is an interface wrapping the basic ProgressBuffer method.
// ProgressBuffer returns a StringBuffer meant to be used as buffer for
// plugin_get_progress().
type ProgressBuffer interface {
	ProgressBuffer() StringBuffer
}

// OpenParamsBuffer is an interface wrapping the basic OpenParamsBuffer method.
// OpenParamsBuffer returns a StringBuffer meant to be used as buffer for
// plugin_list_open_params().
type OpenParamsBuffer interface {
	OpenParamsBuffer() StringBuffer
}
