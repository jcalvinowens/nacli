/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Calvin Owens <calvin@wbinvd.org>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct input_output_ctx {
	void (*begin)(struct input_output_ctx *);
	bool (*push)(struct input_output_ctx *, const uint8_t *, size_t, bool);
	size_t block_size;
	size_t flushbytes;
	size_t written;
	FILE *in;
	FILE *out;
	void *priv;
};

extern void run_input_output(struct input_output_ctx *ctx);

extern void write_str_to_file(const char *path, const char *str, size_t len);
extern const char *read_str_from_file(const char *path);

static inline void cfree(const void *p)
{
	free((void *)p);
}
