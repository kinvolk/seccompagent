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

// This package exports a set of C functions that provide general
// information about the plugin. The exported functions are:
//      uint32_t get_type();
//      uint32_t get_id();
//      char* get_name();
//      char* get_description();
//      char* get_contact();
//      char* get_version();
//      char* get_required_api_version();
//      char* get_event_source();
//      char* get_extract_event_sources();
//
// In almost all cases, your plugin should import this module, unless
// your plugin exports those symbols by other means.
package info

/*
#include "info.h"
*/
import "C"
import (
	"encoding/json"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

var (
	pType                uint32
	pId                  uint32
	pName                ptr.StringBuffer
	pDescription         ptr.StringBuffer
	pContact             ptr.StringBuffer
	pVersion             ptr.StringBuffer
	pRequiredAPIVersion  ptr.StringBuffer
	pEventSource         ptr.StringBuffer
	pExtractEventSources ptr.StringBuffer
)

//export plugin_get_id
func plugin_get_id() uint32 {
	return pId
}

func SetId(id uint32) {
	pId = id
}

//export plugin_get_name
func plugin_get_name() *C.char {
	return (*C.char)(pName.CharPtr())
}

func SetName(name string) {
	pName.Write(name)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	return (*C.char)(pDescription.CharPtr())
}

func SetDescription(desc string) {
	pDescription.Write(desc)
}

//export plugin_get_contact
func plugin_get_contact() *C.char {
	return (*C.char)(pContact.CharPtr())
}

func SetContact(contact string) {
	pContact.Write(contact)
}

//export plugin_get_version
func plugin_get_version() *C.char {
	return (*C.char)(pVersion.CharPtr())
}

func SetVersion(version string) {
	pVersion.Write(version)
}

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	if pRequiredAPIVersion.String() == "" {
		return C.get_default_required_api_version()
	}
	return (*C.char)(pRequiredAPIVersion.CharPtr())
}

func SetRequiredAPIVersion(apiVer string) {
	pRequiredAPIVersion.Write(apiVer)
}

//export plugin_get_event_source
func plugin_get_event_source() *C.char {
	return (*C.char)(pEventSource.CharPtr())
}

func SetEventSource(source string) {
	pEventSource.Write(source)
}

//export plugin_get_extract_event_sources
func plugin_get_extract_event_sources() *C.char {
	if pExtractEventSources.String() == "" {
		pExtractEventSources.Write("[]")
	}
	return (*C.char)(pExtractEventSources.CharPtr())
}

func SetExtractEventSources(sources []string) {
	if len(sources) == 0 {
		pExtractEventSources.Write("[]")
	} else if b, err := json.Marshal(sources); err != nil {
		panic(err)
	} else {
		pExtractEventSources.Write(string(b))
	}
}
