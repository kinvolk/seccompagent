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

package cgo

import (
	"sync/atomic"
)

// Handle is an alternative implementation of cgo.Handle introduced by
// Go 1.17, see https://pkg.go.dev/runtime/cgo. This implementation
// optimizes performance in use cases related to plugins. It is intended
// to be used both as a replacement and as a polyfill for Go versions
// that miss it.
//
// As the original implementation, this provides a way to pass values that
// contain Go pointers between Go and C without breaking the cgo pointer
// passing rules. The underlying type of Handle is guaranteed to fit in
// an integer type that is large enough to hold the bit pattern of any pointer.
// The zero value of a Handle is not valid and thus is safe to use as
// a sentinel in C APIs.

// The performance optimization comes with a limitation: the maximum number
// of handles is capped to a fixed value (see MaxHandle). However, since
// the intended usage is to pass opaque pointers holding the plugin states
// (usually at most two pointers per one instance of a plugin), this hard limit
// is considered acceptable. The usage in other contexts is discuraged.
//
type Handle uintptr

// The max number of handle that can be created.
const MaxHandle = 32 - 1

// NewHandle returns a handle for a given value.
//
// The handle is valid until the program calls Delete on it. The handle
// uses resources, and this package assumes that C code may hold on to
// the handle, so a program must explicitly call Delete when the handle
// is no longer needed.
//
// The intended use is to pass the returned handle to C code, which
// passes it back to Go, which calls Value.
//
// This function panics if called more than MaxHandle times.
func NewHandle(v interface{}) Handle {
	h := atomic.AddUintptr(&handleIdx, 1)
	if h > MaxHandle {
		panic("plugin-sdk-go/cgo: ran out of handle space")
	}

	handles[h] = v
	return Handle(h)
}

// Value returns the associated Go value for a valid handle.
//
// The method panics if the handle is invalid.
func (h Handle) Value() interface{} {
	if h > MaxHandle || handles[h] == &noHandle {
		panic("plugin-sdk-go/cgo: misuse of an invalid Handle")
	}
	return handles[h]
}

// Delete invalidates a handle. This method should only be called once
// the program no longer needs to pass the handle to C and the C code
// no longer has a copy of the handle value.
//
// The method panics if the handle is invalid.
func (h Handle) Delete() {
	if h > MaxHandle || handles[h] == &noHandle {
		panic("plugin-sdk-go/cgo: misuse of an invalid Handle")
	}
	handles[h] = &noHandle
}

func resetHandles() {
	handleIdx = 0
	for i := 0; i <= MaxHandle; i++ {
		handles[i] = &noHandle
	}
}

var (
	handles   [MaxHandle + 1]interface{} // [int]interface{}
	handleIdx uintptr                    // atomic
	noHandle  int
)

func init() {
	resetHandles()
}
