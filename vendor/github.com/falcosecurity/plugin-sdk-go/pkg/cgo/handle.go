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
//
// The performance optimization comes with a limitation: the maximum number
// of valid handles is capped to a fixed value (see MaxHandle).
// However, since the intended usage is to pass opaque pointers holding the
// plugin states (usually at most two pointers per one instance of a plugin),
// this hard limit is considered acceptable.
//
// The thread-safety guarantees have been dropped for further
// performance improvements. The current version of the Plugin API does not
// require thread safety.
//
// The usage in other contexts is discuraged.
type Handle uintptr

// MaxHandle is the largest value that an Handle can hold
const MaxHandle = 32 - 1

var (
	handles  [MaxHandle + 1]interface{} // [int]interface{}
	noHandle int                        = 0
)

func init() {
	resetHandles()
}

// NewHandle returns a handle for a given value.
//
// The handle is valid until the program calls Delete on it. The handle
// uses resources, and this package assumes that C code may hold on to
// the handle, so a program must explicitly call Delete when the handle
// is no longer needed. Programs must not retain deleted handles.
//
// The intended use is to pass the returned handle to C code, which
// passes it back to Go, which calls Value.
//
// The simultaneous number of the valid handles cannot exceed MaxHandle.
// This function panics if there are no more handles available.
// Previously created handles may be made available again when
// invalidated with Delete.
//
// This function is not thread-safe.
func NewHandle(v interface{}) Handle {
	for i := 1; i <= MaxHandle; i++ {
		if handles[i] == &noHandle {
			handles[i] = v
			return Handle(i)
		}
	}
	panic("plugin-sdk-go/cgo: ran out of handle space")
}

// Value returns the associated Go value for a valid handle.
//
// The method panics if the handle is invalid.
// This function is not thread-safe.
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
// This function is not thread-safe.
func (h Handle) Delete() {
	if h > MaxHandle || handles[h] == &noHandle {
		panic("plugin-sdk-go/cgo: misuse of an invalid Handle")
	}
	handles[h] = &noHandle
}

func resetHandles() {
	for i := 0; i <= MaxHandle; i++ {
		handles[i] = &noHandle
	}
}
