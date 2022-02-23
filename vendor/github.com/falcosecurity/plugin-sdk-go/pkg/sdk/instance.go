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

// InstanceState represents the state of a plugin instance created
// with plugin_open().
type InstanceState interface {
}

// Closer is an interface wrapping the basic Destroy method.
// Close deinitializes the resources opened or allocated by a plugin instance.
// This is meant to be used in plugin_close() to release the resources owned
// by a plugin instance. The behavior of Close after the first call
// is undefined.
type Closer interface {
	Close()
}

// Events is an interface wrapping the basic Events and SetEvents
// methods. This is meant to be used as a standard container for a resusable
// list of EventWriters to be used in plugin_next_batch().
type Events interface {
	// Events returns the list of reusable EventWriters.
	Events() EventWriters
	//
	// SetEvents sets the list of reusable EventWriters.
	SetEvents(events EventWriters)
}

// NextBatcher is an interface wrapping the basic NextBatch method.
// NextBatch is meant to be used in plugin_next_batch() to create a batch of
// new events altogether.
//
// The pState argument represents the plugin state, whereas the evt argument
// is an EventWriters representing list the to-be created events.
// The size of the event list dictates the expected size of the batch.
//
// NextBatch can set a timestamp for the to-be created events with the
// SetTimestamp method of the EventWriter interface.
// If not set manually, the framework will set a timestamp automatically.
// NextBatch must be consistent in setting timestamps: either it sets it
// for every event, or for none.
//
// NextBatch returns the number of events created in the batch, which is
// always <= evts.Len(), and a nil error if the call is successful.
// ErrTimeout can be returned to indicate that no new events are currently
// available for the current batch, but that they can be available in future
// calls to NextBatch. ErrEOF can be returned to indicate that no new events
// will be available. After returning ErrEOF once, subsequent calls to
// NextBatch must be idempotent and must keep returning ErrEOF.
// If the returned error is non-nil, the batch of events is discarded.
type NextBatcher interface {
	NextBatch(pState PluginState, evts EventWriters) (int, error)
}

// Progresser is an interface wrapping the basic Progress method.
// Progress is meant to be used in plugin_get_progress() to optionally notify
// the framework about the current event creation progress.
// Progress returns a float64 representing the normalized progress percentage
// such that 0 <= percentage <= 1, and a string representation of the same
// percentage value.
type Progresser interface {
	Progress(pState PluginState) (float64, string)
}
