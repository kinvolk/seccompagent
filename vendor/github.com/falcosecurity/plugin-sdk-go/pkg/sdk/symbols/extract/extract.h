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

#pragma once

#include <stdatomic.h>
#include "../../plugin_info.h"

typedef struct async_extractor_info
{
	// lock
	atomic_int_least32_t lock;

	// input data
	ss_plugin_t *s;
	const ss_plugin_event *evt;
	uint32_t num_fields;
	ss_plugin_extract_field *fields;

	// output data
	int32_t rc;
} async_extractor_info;

async_extractor_info *async_init();
void async_deinit();
