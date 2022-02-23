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
#include <string.h>
*/
import "C"
import (
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

const (
	offsetErrorFmt   = "invalid offset value %d"
	lengthErrorFmt   = "invalid length value %d"
	capacityErrorFmt = "invalid capacity value %d"
	whenceErrorFmt   = "invalid whence value %d"
	bufferErrorFmt   = "invalid buffer value"
)

// Integer limit values.
// todo: math.MaxInt was introduced by golang 1.17 (see https://golang.org/doc/go1.17)
const (
	intSize = 32 << (^uint(0) >> 63) // 32 or 64
	maxInt  = 1<<(intSize-1) - 1
)

// BytesReadWriter is an opaque wrapper for fixed-size memory buffers, that can safely be
// used in the plugin framework in a Go-friendly way. The purpose is to allow safe memory
// access through the read/write interface primitives, regardless of how the buffer is
// physically allocated under the hood. For instance, this can be used to wrap C-allocated
// buffers to hide both the type conversion magic and prevent illegal memory operations.
//
// The io.ReadWriteSeeker interface is leveraged to implement the safe random memory
// access semantic. Note, read-only or write-only access to the memory buffer
// can easily be accomplished by casting instances of this interface to either a io.Reader
// or a io.Writer.
type BytesReadWriter interface {
	io.ReadWriteSeeker
	//
	// BufferPtr returns an unsafe.Pointer that points to the underlying memory buffer.
	BufferPtr() unsafe.Pointer
	//
	// Len returns the total number of accessible bytes for reading and writing.
	Len() int64
	//
	// SetLen sets the total number of accessible bytes for reading and writing.
	// The new length value should not be larger than the underlying memory buffer capacity.
	// If a greater value is given, the length is set to be equal to the capacity.
	// If a value less than zero is given, the length is set to be zero.
	SetLen(len int64)
	//
	// Offset returns the current cursor position relatively to the underlying buffer.
	// The cursor position represents the index of the next byte in the buffer that will
	// be available for read\write operations. This value is altered through the usage of
	// Seek, Read, and Write. By definition, we have that 0 <= Offset() <= Len().
	Offset() int64
}

// NewBytesReadWriter creates a new instance of BytesReadWriter by wrapping the memory pointed
// by the buffer argument. The length argument is the total number of accessible bytes
// for reading and writing. The capacity argument is the number of bytes in the given buffer.
//
// Note that the capacity cannot be changed after creation, and that the length cannot ever exceed
// the capacity.
func NewBytesReadWriter(buffer unsafe.Pointer, length, capacity int64) (BytesReadWriter, error) {
	if buffer == nil {
		return nil, fmt.Errorf(bufferErrorFmt)
	}
	if capacity < 0 || capacity > maxInt {
		return nil, fmt.Errorf(capacityErrorFmt, capacity)
	}
	if length < 0 || length > capacity {
		return nil, fmt.Errorf(lengthErrorFmt, length)
	}
	// Inspired by: https://stackoverflow.com/a/66218124
	var bytes []byte
	(*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Data = uintptr(buffer)
	(*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Len = int(capacity)
	(*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Cap = int(capacity)
	return &bytesReadWriter{
		buffer:     buffer,
		bytesAlias: bytes,
		offset:     0,
		len:        length,
	}, nil
}

type bytesReadWriter struct {
	offset     int64
	len        int64
	buffer     unsafe.Pointer
	bytesAlias []byte
}

func (b *bytesReadWriter) Read(p []byte) (n int, err error) {
	n = 0
	pLen := len(p)
	for i := 0; i < pLen; i++ {
		if b.offset >= b.len {
			err = io.EOF
			return
		}
		p[i] = b.bytesAlias[b.offset]
		b.offset++
		n++
	}
	return
}

func (b *bytesReadWriter) Write(p []byte) (n int, err error) {
	n = 0
	for _, v := range p {
		if b.offset >= b.len {
			err = io.ErrShortWrite
			return
		}
		b.bytesAlias[b.offset] = v
		b.offset++
		n++
	}
	return
}

func (b *bytesReadWriter) Len() int64 {
	return b.len
}

func (b *bytesReadWriter) SetLen(len int64) {
	if len < 0 {
		b.len = 0
	} else if len > int64(cap(b.bytesAlias)) {
		b.len = int64(cap(b.bytesAlias))
	} else {
		b.len = len
	}
}

func (b *bytesReadWriter) Offset() int64 {
	return b.offset
}

func (b *bytesReadWriter) Seek(offset int64, whence int) (int64, error) {
	if offset < 0 {
		return b.offset, fmt.Errorf(offsetErrorFmt, offset)
	}
	switch whence {
	case io.SeekStart:
		b.offset = offset
		if offset > b.len {
			return b.offset, fmt.Errorf(offsetErrorFmt, offset)
		}
	case io.SeekCurrent:
		if offset > b.len-b.offset {
			return b.offset, fmt.Errorf(offsetErrorFmt, offset)
		}
		b.offset = b.offset + offset
	case io.SeekEnd:
		if offset > b.len {
			return b.offset, fmt.Errorf(offsetErrorFmt, offset)
		}
		b.offset = b.len - offset
	default:
		return b.offset, fmt.Errorf(whenceErrorFmt, whence)
	}
	return b.offset, nil
}

func (b *bytesReadWriter) BufferPtr() unsafe.Pointer {
	return b.buffer
}
