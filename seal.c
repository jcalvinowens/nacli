/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Calvin Owens <calvin@wbinvd.org>
 */

#include "lib.h"

#include <err.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sodium.h>

struct seal_ctx {
	uint8_t pk[crypto_box_PUBLICKEYBYTES];
	uint8_t sk[crypto_box_SECRETKEYBYTES];
	crypto_secretstream_xchacha20poly1305_state ctx;
};

static void seal_begin(struct input_output_ctx *ctx)
{
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	uint8_t hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t ckey[sizeof(key) + crypto_box_SEALBYTES];
	struct seal_ctx *sctx = ctx->priv;

	crypto_secretstream_xchacha20poly1305_keygen(key);
	crypto_secretstream_xchacha20poly1305_init_push(&sctx->ctx, hdr, key);
	crypto_box_seal(ckey, key, sizeof(key), sctx->pk);
	fwrite(ckey, 1, sizeof(ckey), ctx->out);
	fwrite(hdr, 1, sizeof(hdr), ctx->out);
	ctx->written = 0;
}

static void unseal_begin(struct input_output_ctx *ctx)
{
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	uint8_t hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t ckey[sizeof(key) + crypto_box_SEALBYTES];
	struct seal_ctx *sctx = ctx->priv;

	if (fread(ckey, 1, sizeof(ckey), ctx->in) != sizeof(ckey))
		err(1, "EOF before sealed input stream key");

	crypto_scalarmult_base(sctx->pk, sctx->sk);
	if (crypto_box_seal_open(key, ckey, sizeof(ckey), sctx->pk, sctx->sk))
		errx(1, "Corrupt sealed input stream key");

	if (fread(hdr, 1, sizeof(hdr), ctx->in) != sizeof(hdr))
		err(1, "EOF before sealed input stream header");

	if (crypto_secretstream_xchacha20poly1305_init_pull(&sctx->ctx, hdr,
							    key))
		errx(1, "Corrupt sealed input stream header");

	ctx->written = 0;
}

static void seal_push(struct input_output_ctx *ctx, const uint8_t *data,
		      size_t len, bool eof)
{
	uint8_t tmp[len + crypto_secretstream_xchacha20poly1305_ABYTES];
	struct seal_ctx *sctx = ctx->priv;
	uint8_t tag = 0;

	if (len == 0)
		errx(1, "Zero-length push should never happen");

	if (eof)
		tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;

	crypto_secretstream_xchacha20poly1305_push(&sctx->ctx, tmp, NULL, data,
						   len, NULL, 0, tag);

	if (fwrite(tmp, 1, sizeof(tmp), ctx->out) != sizeof(tmp))
		err(1, "Can't write output");

	ctx->written += sizeof(tmp);
}

static void unseal_push(struct input_output_ctx *ctx, const uint8_t *data,
			size_t len, bool eof)
{
	uint8_t tmp[len - crypto_secretstream_xchacha20poly1305_ABYTES];
	struct seal_ctx *sctx = ctx->priv;
	uint8_t tag;

	if (crypto_secretstream_xchacha20poly1305_pull(
		    &sctx->ctx, tmp, NULL, &tag, data, len, NULL, 0))
		errx(1, "Corrupt data in sealed input stream");

	if (fwrite(tmp, 1, sizeof(tmp), ctx->out) != sizeof(tmp))
		err(1, "Can't write output");

	if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
		errx(1, "Truncated sealed input stream");

	ctx->written += sizeof(tmp);
	if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof)
		errx(1, "End of signed data before EOF");
}

static int sk_from_hex(uint8_t *sk, const char *hex)
{
	return sodium_hex2bin(sk, crypto_box_SECRETKEYBYTES, hex,
			      crypto_box_SECRETKEYBYTES * 2, NULL, NULL, NULL);
}

static int pk_from_hex(uint8_t *pk, const char *hex)
{
	return sodium_hex2bin(pk, crypto_box_PUBLICKEYBYTES, hex,
			      crypto_box_PUBLICKEYBYTES * 2, NULL, NULL, NULL);
}

static int show_help(void)
{
	puts("Usage: seal [-K [path] | -p <pubkey_hex_str> | "
	     "-S <seckey_file_path>] [-i <in>] [out]");
	return EXIT_FAILURE;
}

static void nothing(int signo __attribute__((unused)))
{
}

int main(int argc, char **argv)
{
	static const char argf[] = ":K:P:S:p:i:o:b:f:h";
	static const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct sigaction ignore_action = {
		.sa_handler = SIG_IGN,
	};
	struct sigaction nothing_action = {
		.sa_handler = nothing,
	};
	struct seal_ctx sctx;
	struct input_output_ctx ctx = {
		.block_size =
			1024 - crypto_secretstream_xchacha20poly1305_ABYTES,
		.flushbytes = SIZE_MAX,
		.priv = &sctx,
	};
	const char *keyfile = NULL;
	const char *in_path = strdup("-");
	const char *out_path = strdup("-");
	bool unseal = false;
	bool seal = false;
	bool keygen = false;

	if (sodium_init() < 0)
		errx(1, "Unable to initialize libsodium");

	if (isatty(STDIN_FILENO))
		sigaction(SIGINT, &nothing_action, NULL);
	else
		sigaction(SIGINT, &ignore_action, NULL);

	sigaction(SIGPIPE, &ignore_action, NULL);
	sigaction(SIGHUP, &ignore_action, NULL);

	while (1) {
		int i = getopt_long(argc, argv, argf, opts, NULL);
		char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
		const char *tmp;

		switch (i) {
		case 'K':
			keyfile = strdup(optarg);
			keygen = true;
			break;
		case 'S':
			unseal = true;
			tmp = read_str_from_file(optarg);
			if (sk_from_hex(sctx.sk, tmp))
				errx(1, "Bad secret key in '%s'", optarg);
			cfree(tmp);
			break;
		case 'p':
			seal = true;
			if (pk_from_hex(sctx.pk, optarg))
				errx(1, "Bad public key: '%s'", optarg);
			break;
		case 'P':
			tmp = read_str_from_file(optarg);
			if (sk_from_hex(sctx.sk, tmp))
				errx(1, "Bad public key: '%s'", tmp);
			crypto_scalarmult_base(sctx.pk, sctx.sk);
			sodium_bin2hex(pk_hex, sizeof(pk_hex), sctx.pk,
				       sizeof(sctx.pk));
			cfree(tmp);
			puts(pk_hex);
			goto out;
		case 'i':
			cfree(in_path);
			in_path = strdup(optarg);
			break;
		case 'o':
			cfree(out_path);
			out_path = strdup(optarg);
			break;
		case 'b':
			ctx.block_size = atol(optarg);
			if (ctx.block_size <= 0)
				errx(1, "Bad block size: %ld", ctx.block_size);
			break;
		case 'f':
			ctx.flushbytes = atol(optarg);
			break;
		case ':':
			switch (optopt) {
			case 'K':
				keyfile = strdup("seal.key");
				keygen = true;
				break;
			case 'f':
				ctx.flushbytes = SIZE_MAX - 1;
				break;
			case 'o':
			case 'i':
				break;
			default:
				fprintf(stderr, "%c requires an argument",
					optopt);

				return show_help();
			}
			break;
		case 'h':
		default:
			return show_help();
		case -1:
			goto done;
		}
	}
done:
	if (argc - optind > 0)
		warnx("Ignoring %d positional argument(s)", argc - optind);

	if (keygen) {
		char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
		char sk_hex[crypto_box_SECRETKEYBYTES * 2 + 1];

		crypto_box_keypair(sctx.pk, sctx.sk);
		sodium_bin2hex(pk_hex, sizeof(pk_hex), sctx.pk,
			       sizeof(sctx.pk));
		sodium_bin2hex(sk_hex, sizeof(sk_hex), sctx.sk,
			       sizeof(sctx.sk));
		fprintf(stdout, "%s\n", pk_hex);
		write_str_to_file(keyfile, sk_hex, sizeof(sk_hex) - 1);
		chmod(keyfile, 0600);
		goto out;
	}

	if (!strcmp(out_path, "-")) {
		ctx.out = stdout;
	} else {
		ctx.out = fopen(out_path, "w+");
		if (!ctx.out)
			err(1, "Can't open output '%s'", out_path);
	}

	if (!strcmp(in_path, "-")) {
		ctx.in = stdin;
	} else {
		ctx.in = fopen(in_path, "r");
		if (!ctx.in)
			err(1, "Can't open input '%s'", in_path);
	}

	if (seal) {
		ctx.begin = seal_begin;
		ctx.push = seal_push;
		run_input_output(&ctx);
	} else if (unseal) {
		ctx.begin = unseal_begin;
		ctx.push = unseal_push;
		ctx.block_size += crypto_secretstream_xchacha20poly1305_ABYTES;
		run_input_output(&ctx);
	} else {
		return show_help();
	}

	if (strcmp(out_path, "-")) {
		if (ctx.flushbytes != SIZE_MAX) {
			fflush(ctx.out);
			fsync(fileno(ctx.out));
		}

		fclose(ctx.out);
	}

out:
	cfree(keyfile);
	cfree(in_path);
	cfree(out_path);
	return 0;
}
