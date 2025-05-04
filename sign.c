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

struct sign_ctx {
	uint8_t pk[crypto_sign_PUBLICKEYBYTES];
	uint8_t sk[crypto_sign_SECRETKEYBYTES];
	uint8_t sig[crypto_sign_BYTES];
	crypto_sign_state ctx;
};

static void sign_begin(struct input_output_ctx *ctx)
{
	struct sign_ctx *sctx = ctx->priv;
	crypto_sign_init(&sctx->ctx);
}

static void sign_push(struct input_output_ctx *ctx, const uint8_t *data,
		      size_t len, bool eof __attribute__((unused)))
{
	struct sign_ctx *sctx = ctx->priv;

	if (len == 0)
		errx(1, "Zero-length push should never happen");

	crypto_sign_update(&sctx->ctx, data, len);
}

static int sig_from_hex(uint8_t *sig, const char *hex)
{
	return sodium_hex2bin(sig, crypto_sign_BYTES, hex,
			      crypto_sign_BYTES * 2, NULL, NULL, NULL);
}

static int sk_from_hex(uint8_t *sk, const char *hex)
{
	return sodium_hex2bin(sk, crypto_sign_SECRETKEYBYTES, hex,
			      crypto_sign_SECRETKEYBYTES * 2, NULL, NULL, NULL);
}

static int pk_from_hex(uint8_t *pk, const char *hex)
{
	return sodium_hex2bin(pk, crypto_sign_PUBLICKEYBYTES, hex,
			      crypto_sign_PUBLICKEYBYTES * 2, NULL, NULL, NULL);
}

static int show_help(void)
{
	puts("Usage: sign [-K [path] | -p <pubkey_hex_str> -v <sig_hex> | "
	     "-S <seckey_file_path>] [-i <in>]");
	return EXIT_FAILURE;
}

static void nothing(int signo __attribute__((unused)))
{
}

int main(int argc, char **argv)
{
	static const char argf[] = ":K:P:S:p:i:v:h";
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
	struct sign_ctx sctx;
	struct input_output_ctx ctx = {
		.block_size =
			4096 - crypto_secretstream_xchacha20poly1305_ABYTES,
		.priv = &sctx,
	};
	const char *keyfile = NULL;
	const char *in_path = strdup("-");
	bool sign = false;
	bool verify = false;
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
		char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
		const char *tmp;

		switch (i) {
		case 'K':
			keyfile = strdup(optarg);
			keygen = true;
			break;
		case 'S':
			sign = true;
			tmp = read_str_from_file(optarg);
			if (sk_from_hex(sctx.sk, tmp))
				errx(1, "Bad secret key in '%s'", optarg);
			cfree(tmp);
			break;
		case 'p':
			if (pk_from_hex(sctx.pk, optarg))
				errx(1, "Bad public key: '%s'", optarg);
			break;
		case 'P':
			tmp = read_str_from_file(optarg);
			if (sk_from_hex(sctx.sk, tmp))
				errx(1, "Bad public key: '%s'", tmp);
			crypto_sign_ed25519_sk_to_pk(sctx.pk, sctx.sk);
			sodium_bin2hex(pk_hex, sizeof(pk_hex), sctx.pk,
				       sizeof(sctx.pk));
			cfree(tmp);
			puts(pk_hex);
			goto out;
		case 'v':
			verify = true;
			if (sig_from_hex(sctx.sig, optarg))
				errx(1, "Bad signature: '%s'", optarg);
			break;
		case 'i':
			cfree(in_path);
			in_path = strdup(optarg);
			break;
		case ':':
			switch (optopt) {
			case 'K':
				keyfile = strdup("sign.key");
				keygen = true;
				break;
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
		char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
		char sk_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];

		crypto_sign_keypair(sctx.pk, sctx.sk);
		sodium_bin2hex(pk_hex, sizeof(pk_hex), sctx.pk,
			       sizeof(sctx.pk));
		sodium_bin2hex(sk_hex, sizeof(sk_hex), sctx.sk,
			       sizeof(sctx.sk));
		puts(pk_hex);
		write_str_to_file(keyfile, sk_hex, sizeof(sk_hex) - 1);
		chmod(keyfile, 0600);
		goto out;
	}

	if (!strcmp(in_path, "-")) {
		ctx.in = stdin;
	} else {
		ctx.in = fopen(in_path, "r");
		if (!ctx.in)
			err(1, "Can't open input '%s'", in_path);
	}

	ctx.begin = sign_begin;
	ctx.push = sign_push;

	if (sign) {
		char sig_hex[crypto_sign_BYTES * 2 + 1];
		uint8_t sig[crypto_sign_BYTES];

		run_input_output(&ctx);
		crypto_sign_final_create(&sctx.ctx, sig, NULL, sctx.sk);
		sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));
		puts(sig_hex);
	} else if (verify) {
		run_input_output(&ctx);
		if (crypto_sign_final_verify(&sctx.ctx, sctx.sig, sctx.pk) != 0)
			errx(1, "Bad signature");
	} else {
		return show_help();
	}

out:
	cfree(in_path);
	cfree(keyfile);
	return 0;
}
