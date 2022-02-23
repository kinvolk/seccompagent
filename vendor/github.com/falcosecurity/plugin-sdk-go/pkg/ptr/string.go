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

package ptr

/*
#include <stdlib.h>
*/
import "C"
import (
	"reflect"
	"unsafe"
)

const (
	cStringNullTerminator = byte(0)
)

// GoString converts a C string to a Go string. This is analoguous
// to C.GoString, but avoids unnecessary memory allcations and copies.
// The string length is determined by invoking strlen on the passed
// memory pointer.
// Note that the returned string is an aliased view of the underlying
// C-allocated memory. As such, writing inside the memory will cause
// the string contents to change. Accordingly, unsafe memory management,
// such as unexpectedly free-ing the underlying C memory, can cause
// non-deterministic behavior on the Go routines using the returned string.
func GoString(charPtr unsafe.Pointer) string {
	if charPtr == nil {
		return ""
	}

	// We manually implement strlen to avoid an unnecessary Go -> C call.
	// See: https://github.com/torvalds/linux/blob/f6274b06e326d8471cdfb52595f989a90f5e888f/lib/string.c#L558
	var len int
	for len = 0; *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(charPtr)) + uintptr(len))) != cStringNullTerminator; len++ {
		// nothing
	}

	var res string
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Data = uintptr(charPtr)
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Len = len
	return res
}

// StringBuffer represents a buffer for C-allocated null-terminated strings
// in a Go-friendly way. This is an implementation of the sdk.StringBuffer
// interface. The underlying memory buffer is allocated and resized
// automatically. The buffer allocation happens lazily at the first call
// to Write. If during a call to Write the converted string is too large
// to fit in the buffer, it gets resized automatically to a proper size.
type StringBuffer struct {
	cPtr *C.char
	len  int
}

func (s *StringBuffer) Write(str string) {
	if s.cPtr == nil || len(str) > s.len {
		if s.cPtr != nil {
			C.free(unsafe.Pointer(s.cPtr))
		}
		s.cPtr = (*C.char)(C.malloc((C.size_t)(len(str) + 1)))
	}

	p := (*[1 << 30]byte)(unsafe.Pointer(s.cPtr))
	copy(p[:], str)
	p[len(str)] = cStringNullTerminator
	s.len = len(str)
}

func (s *StringBuffer) CharPtr() unsafe.Pointer {
	return unsafe.Pointer(s.cPtr)
}

func (s *StringBuffer) String() string {
	return GoString(unsafe.Pointer(s.cPtr))
}

func (s *StringBuffer) Free() {
	C.free(unsafe.Pointer(s.cPtr))
}
