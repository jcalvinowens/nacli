/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Calvin Owens <calvin@wbinvd.org>
 */

#include "lib.h"

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

static size_t read_one(struct input_output_ctx *ctx, uint8_t *buf, size_t len)
{
	size_t off = 0;

	do {
		off += fread(buf + off, 1, len - off, ctx->in);
		if (ferror(ctx->in))
			err(1, "Unable to read input");

	} while (!feof(ctx->in) && off != len);

	return off;
}

void run_input_output(struct input_output_ctx *ctx)
{
	uint8_t buf[2][ctx->block_size];
	size_t len;
	int v = 1;

	/*
	 * We have to fit a square peg in a round hole here: libc stdio returns
	 * EOF *after* the final block has been read, but in some cases the
	 * callback requires the final block itself to be flagged as EOF.
	 */

	ctx->begin(ctx);
	len = read_one(ctx, buf[0], ctx->block_size);
	if (len < ctx->block_size)
		goto out;

	do {
		len = read_one(ctx, buf[v], ctx->block_size);
		if (ctx->push(ctx, buf[!v], ctx->block_size, len == 0)) {
			/*
			 * Early EOF lets us ignore tailing junk on ciphertext,
			 * so the user can append arbitrary data to the files.
			 */
			return;
		}

		v = !v;

		if (ctx->written >= ctx->flushbytes) {
			fflush(ctx->out);
			fdatasync(fileno(ctx->out));
			ctx->written = 0;
		}

	} while (len == ctx->block_size);

out:
	if (len > 0)
		ctx->push(ctx, buf[!v], len, true);
}

void write_str_to_file(const char *path, const char *str, size_t len)
{
	FILE *f = fopen(path, "w+");
	if (!f)
		err(1, "Can't open '%s'", path);

	if (fwrite(str, 1, len, f) != len)
		err(1, "Can't write to '%s'", path);

	fwrite("\n", 1, 1, f);
	if (fclose(f))
		err(1, "Can't close '%s'", path);
}

const char *read_str_from_file(const char *path)
{
	char tmp[1024];
	size_t len;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		err(1, "Can't open '%s'", path);

	len = fread(tmp, 1, sizeof(tmp) - 1, f);
	tmp[len] = '\0';

	if (fclose(f))
		err(1, "Can't close '%s'", path);

	return strdup(tmp);
}
