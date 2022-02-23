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

// Package plugins and its subpackages provide high-level constructs
// to easily develop plugins, abstracting all the low-level
// details of the plugin framework. This bundles the main plugin developer
// tools provided by the SDK. Plugin developers are encouraged to use the
// constructs of the plugins package for their plugins.
//
// This packages depends on the lower-level prebuilt C symbols implementations
// of the sdk/symbols package. For some use cases, developers can consider
// using the the sdk/symbols package to customize their usage of the SDK.
// This is meaningful only if developers wish to manually write part of the
// low-level C details of the plugin framework, but still want to use some
// parts of the SDK. This is discouraged if not for advanced use cases only,
// and developers are instead encouraged to rely on the plugins package to
// build their plugins.
//
// Most of the time, a plugin author only needs to import the following packages,
// which provide the "default" streamlined interfaces to implementing a source
// or extractor plugin:
//  "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
//  "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
//  "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/{source,extractor}"
//
package plugins
