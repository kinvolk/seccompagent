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

// Package sdk provides definitions and constructs for developers that
// would like to write Falcosecurity Plugins (https://falco.org/docs/plugins/)
// in Go.
//
// Before using this package, review the developer's guide
// (https://falco.org/docs/plugins/developers_guide/) which fully documents
// the API and provides best practices for writing plugins.
// The developer's guide includes a walkthrough
// (https://falco.org/docs/plugins/developers_guide/#example-go-plugin-dummy)
// of a plugin written in Go that uses this package.
//
// For a quick start, you can refer to the provided examples of extractor plugin
// (https://github.com/falcosecurity/plugin-sdk-go/tree/main/examples/extractor),
// source plugin
// (https://github.com/falcosecurity/plugin-sdk-go/tree/main/examples/source),
// and source plugin with extraction
// (https://github.com/falcosecurity/plugin-sdk-go/tree/main/examples/full).
//
// This SDK is designed to be layered with different levels of abstraction:
//
// 1. The "sdk/plugins" package provide high-level constructs to easily develop
// plugins in a Go-friendly way, by abstracting all the low-level details
// of the plugin framework and by avoiding the need of useless boilerplate code.
// This package is the way to go for developers to start building plugins.
//
// 2. The "sdk/symbols" package provide prebuilt implementations for all the C
// symbols that need to be exported by the plugin in order to be accepted by the
// framework. The prebuilt symbols handle all the complexity of bridging the C
// symbols and the Go runtime. Each subpackage is not internal, and can be used
// by advanced plugin developers to achieve a custom usage of the SDK symbols.
// This option is a strongly discouraged, as plugins must generally be
// developed using the more high-level constructs of the "sdk/plugins" package.
// This package is also used internally, and may be subject to more frequent
// breaking changes.
//
// 3. The "sdk" package provides basic definitions and constructs necessary to develop
// plugins. The SDK describes the behavior of plugins as a set of minimal and
// composable interfaces, to be used flexibly in other packages.
//
package sdk
