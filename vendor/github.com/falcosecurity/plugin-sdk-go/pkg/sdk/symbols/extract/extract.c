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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include "extract.h"

enum worker_state
{
	WAIT = 0,
	DATA_REQ = 1,
	EXIT_REQ = 2,
	EXIT_ACK = 3,
};

static async_extractor_info *s_async_extractor_ctx = NULL;

async_extractor_info *async_init()
{
	s_async_extractor_ctx = (async_extractor_info *)malloc(sizeof(async_extractor_info));
	return s_async_extractor_ctx;
}

void async_deinit()
{
	free(s_async_extractor_ctx);
	s_async_extractor_ctx = NULL;
}

// Defined in extract.go
extern int32_t plugin_extract_fields_sync(ss_plugin_t *s,
										  const ss_plugin_event *evt,
										  uint32_t num_fields,
										  ss_plugin_extract_field *fields);

static inline int32_t async_extract_request(ss_plugin_t *s,
											const ss_plugin_event *evt,
											uint32_t num_fields,
											ss_plugin_extract_field *fields)
{
	// Since no concurrent requests are supported,
	// we assume worker is already in WAIT state

	// Set input data
	s_async_extractor_ctx->s = s;
	s_async_extractor_ctx->evt = evt;
	s_async_extractor_ctx->num_fields = num_fields;
	s_async_extractor_ctx->fields = fields;

	// notify data request
	atomic_store_explicit(&s_async_extractor_ctx->lock, DATA_REQ, memory_order_seq_cst);

	// busy-wait until worker completation
	while (atomic_load_explicit(&s_async_extractor_ctx->lock, memory_order_seq_cst) != WAIT);

	return s_async_extractor_ctx->rc;
}

// This is the plugin API function. If s_async_extractor_ctx is
// non-NULL, it calls the async extractor function. Otherwise, it
// calls the synchronous extractor function.
int32_t plugin_extract_fields(ss_plugin_t *s,
							  const ss_plugin_event *evt,
							  uint32_t num_fields,
							  ss_plugin_extract_field *fields)
{
	if (s_async_extractor_ctx != NULL)
	{
		return async_extract_request(s, evt, num_fields, fields);
	}

	return plugin_extract_fields_sync(s, evt, num_fields, fields);
}
