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
#include <stdlib.h>
#include "plugin_info.h"
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

// EventWriter can be used to represent events produced by a plugin.
// This interface is meant to be used in the next/next_batch.
//
// Data inside an event can only be accessed in write-only mode
// through the io.Writer interface returned by the Writer method.
//
// Instances of this interface should be retrieved through the Get
// method of sdk.EventWriters.
type EventWriter interface {
	// Writer returns an instance of io.Writer that points to the
	// event data. This is the only way to write inside the event data.
	//
	// Each invocation of Writer clears the event data and sets its
	// size to zero. As such, consequent invocations of Writer can
	// potentially return two distinct instances of io.Writer, and
	// any data written inside the event would be erased.
	Writer() io.Writer
	//
	// SetTimestamp sets the timestamp of the event.
	SetTimestamp(value uint64)
}

// EventReader can be used to represent events passed by the framework
// to the plugin. This interface is meant to be used during extraction.
//
// Data inside an event can only be accessed in read-only mode
// through the io.Reader interface returned by the Reader method.
type EventReader interface {
	// EventNum returns the number assigned to the event by the framework.
	EventNum() uint64
	//
	// Timestamp returns the timestamp of the event.
	Timestamp() uint64
	//
	// Reader returns an instance of io.ReadSeeker that points to the
	// event data. This is the only way to read from the event data.
	//
	// This method returns an instance of io.ReadSeeker to leave the door
	// open for seek-related optimizations, which could be useful in the
	// field extraction use case.
	Reader() io.ReadSeeker
}

// EventWriters represent a list of sdk.EventWriter to be used inside
// plugins. This interface hides the complexities related to the internal
// representation of C strutures and to the optimized memory management.
// Internally, this wraps an array of ss_plugin_event C structs that are
// compliant with the symbols and APIs of the plugin framework.
// The underlying C array can be accessed through the ArrayPtr method as
// an unsafe.Pointer. Manually writing inside the C array might break the
// internal logic of sdk.EventWriters and lead to undefined behavior.
//
// This is intended to be used as a slab memory allocator. EventWriters
// are supposed to be stored inside the plugin instance state to avoid
// useless reallocations, and should be used to create plugin events and
// write their data. Unlike slices, the events contained in the list
// can only be accessed by using the Get and Len methods to enforce safe
// memory accesses. Ideally, the list is meant to be large enough to contain
// the maximum number of events that the plugin is capable of producing with
// plugin_next_batch.
type EventWriters interface {
	// Get returns an instance of sdk.EventWriter at the eventIndex
	// position inside the list.
	Get(eventIndex int) EventWriter
	//
	// Len returns the size of the list, namely the number of events
	// it contains. Using Len coupled with Get allows iterating over
	// all the events of the list.
	Len() int
	//
	// ArrayPtr return an unsafe pointer to the underlying C array of
	// ss_plugin_event. The returned pointer should only be used for
	// read tasks or for being passed to the plugin framework.
	// Writing in the memory pointed by this pointer is unsafe and might
	// lead to non-deterministic behavior.
	ArrayPtr() unsafe.Pointer
	//
	// Free deallocates any memory used by the list that can't be disposed
	// through garbage collection. The behavior of Free after the first call
	// is undefined.
	Free()
}

type eventWriters struct {
	evts []*eventWriter
}

// NewEventWriters creates a new instance of sdk.EventWriters.
// The size argument indicates the length of the list, which is the amount
// of events contained. Then dataSize argument indicates the maximum data
// size of each event.
func NewEventWriters(size, dataSize int64) (EventWriters, error) {
	if size < 1 {
		return nil, fmt.Errorf("invalid size: %d", size)
	}
	if dataSize < 0 || dataSize > C.UINT32_MAX {
		return nil, fmt.Errorf("invalid dataSize: %d", dataSize)
	}

	ret := &eventWriters{
		evts: make([]*eventWriter, size),
	}
	pluginEvtArray := (*C.ss_plugin_event)(C.malloc((C.size_t)(size * C.sizeof_ss_plugin_event)))
	var err error
	for i := range ret.evts {
		// get i-th element of pluginEvtArray
		evtPtr := unsafe.Pointer(uintptr(unsafe.Pointer(pluginEvtArray)) + uintptr(i*C.sizeof_ss_plugin_event))
		if ret.evts[i], err = newEventWriter(evtPtr, dataSize); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (p *eventWriters) Get(eventIndex int) EventWriter {
	return p.evts[eventIndex]
}

func (p *eventWriters) Len() int {
	return len(p.evts)
}

func (p *eventWriters) Free() {
	for _, pe := range p.evts {
		pe.free()
	}
	C.free( /*(*C.ss_plugin_event)*/ p.ArrayPtr())
}

func (p *eventWriters) ArrayPtr() unsafe.Pointer {
	return p.evts[0].ssPluginEvt
}

type eventWriter struct {
	data        ptr.BytesReadWriter
	dataSize    int64
	ssPluginEvt unsafe.Pointer
}

func newEventWriter(evtPtr unsafe.Pointer, dataSize int64) (*eventWriter, error) {
	evt := (*C.ss_plugin_event)(evtPtr)
	evt.ts = C.uint64_t(C.UINT64_MAX)
	evt.data = (*C.uint8_t)(C.malloc(C.size_t(dataSize)))
	evt.datalen = 0
	brw, err := ptr.NewBytesReadWriter(unsafe.Pointer(evt.data), int64(dataSize), int64(dataSize))

	if err != nil {
		return nil, err
	}

	return &eventWriter{
		ssPluginEvt: evtPtr,
		data:        brw,
		dataSize:    dataSize,
	}, nil
}

func (p *eventWriter) Writer() io.Writer {
	p.data.SetLen(p.dataSize)
	p.data.Seek(0, io.SeekStart)
	(*C.ss_plugin_event)(p.ssPluginEvt).datalen = 0
	return p
}

func (p *eventWriter) Write(data []byte) (n int, err error) {
	n, err = p.data.Write(data)
	if err != nil {
		return
	}
	(*C.ss_plugin_event)(p.ssPluginEvt).datalen += C.uint32_t(n)
	return
}

func (p *eventWriter) SetTimestamp(value uint64) {
	(*C.ss_plugin_event)(p.ssPluginEvt).ts = C.uint64_t(value)
}

func (p *eventWriter) free() {
	C.free(unsafe.Pointer((*C.ss_plugin_event)(p.ssPluginEvt).data))
	p.data = nil
}

type eventReader C.ss_plugin_event

// NewEventReader wraps a pointer to a ss_plugin_event C structure to create
// a new instance of EventReader. It's not possible to check that the pointer is valid.
// Passing an invalid pointer may cause undefined behavior.
func NewEventReader(ssPluginEvt unsafe.Pointer) EventReader {
	return (*eventReader)(ssPluginEvt)
}

func (e *eventReader) Reader() io.ReadSeeker {
	brw, _ := ptr.NewBytesReadWriter(unsafe.Pointer(e.data), int64(e.datalen), int64(e.datalen))
	return brw
}

func (e *eventReader) Timestamp() uint64 {
	return uint64(e.ts)
}

func (e *eventReader) EventNum() uint64 {
	return uint64(e.evtnum)
}
