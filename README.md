# nacli: Command line tools based on libsodium

A small suite of simple portable "shell frontends" for commonly used
functionality in libsodium.

## Supported commands

* seal (`crypto_box_seal()` and `crypto_secretstream()`)
* sign (`crypto_sign()`)

### The following planned commands are not yet complete:

* TODO auth (`crypto_auth()`)
* TODO authseal (`crypto_box()` and `crypto_secretstream()`)
* TODO crypt (`crypto_secretstream()`)
* TODO hash (`crypto_generichash()`)
* TODO kxpipe (`crypto_kx_client_session_keys()`)
* TODO pwhash (`crypto_pwhash()`)
* TODO shorthash (`crypto_shorthash()`)

## Building

Install libsodium as appropriate for your system:

```
sudo emerge dev-libs/libsodium  # Gentoo
sudo apt install libsodium-dev  # Debian
sudo dnf install libsodium-devel  # Fedora
sudo pkg_add -v libsodium  # OpenBSD
```

Then run make:

```
$ make  # Linux
$ CPATH=/usr/local/include LIBRARY_PATH=/usr/local/lib gmake  # BSD
```

# Command Reference

## Seal

The `seal` command allows for one way anonymous encryption using a keypair: only
the public key is needed to encrypt, and the corresponding secret key is
required to decrypt.

Use `-K` to generate a keypair:

```
$ ./seal -K
c3778c92ddfa906f42026a509e10bac4157c523688d9af80d00d951fa40cd676
$ cat seal.key
95c3778312b797ea24b792cadb9bfa243427fc4f502fd8d2921527fc161dcb7f
```

The secret key is written to the path passed to `-K` (or "seal.key" if omitted),
and the public key is printed to the console. You can use `-P` to compute the
public key from a secret key:

```
$ ./seal -P seal.key
c3778c92ddfa906f42026a509e10bac4157c523688d9af80d00d951fa40cd676
```

To encrypt a message, pass the public key to `-p`:

```
$ echo 'Attack at dawn!' | ./seal -p c3778c92ddfa906f42026a509e10bac4157c523688d9af80d00d951fa40cd676 -o msg.sealed
```

To decrypt a message, pass the secret key file path to `-S`:

```
$ ./seal -S seal.key -i msg.sealed
Attack at dawn!
```

The `-b` parameter controls the block size. If you change the default (1K), you
must use the same value for decryption.

The `-f` parameter forces an `fsync()` call every N bytes. If no N is specified,
it forces an `fsync()` after EOF. By default, `fsync()` is never called at all.

See also:

* [sealed\_boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
* [secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream)

## Sign

The `sign` command creates and verifies signatures using a keypair.

Use `-K` to generate a keypair:

```
$ ./sign -K
1fbdd787d457c088e0fb1afe472f1fff4e4d5574f6eb91dd3a3c0380ea6d3601
$ cat sign.key
000f2994534bbc1dba1c026e8699c90af8f1c8d4fe962ae109583cb74b1a59251fbdd787d457c088e0fb1afe472f1fff4e4d5574f6eb91dd3a3c0380ea6d3601
```

Use `-S` to sign a message with the secret key:

```
$ echo 'Attack at dawn!' | ./sign -S sign.key
07ded208cdbd020b9d0898af0014bf0f513b9115cf36d4afd2797c5eca9e96be9d5813923161e1cbe7eac4ea124b565331ee9206f6f3b23c4a190638dd42c40f
```

Use `-v` to verify a signature with the public key passed to `-p`:

```
$ echo 'Attack at dawn!' | ./sign -p 1fbdd787d457c088e0fb1afe472f1fff4e4d5574f6eb91dd3a3c0380ea6d3601 -v 07ded208cdbd020b9d0898af0014bf0f513b9115cf36d4afd2797c5eca9e96be9d5813923161e1cbe7eac4ea124b565331ee9206f6f3b23c4a190638dd42c40f && echo "VERIFIED"
VERIFIED
```

The secret key is written to the path passed to `-K` (or "sign.key" if omitted),
and the public key is printed to the console. You can use `-P` to compute the
public key from a secret key:

```
$ ./sign -P sign.key
1fbdd787d457c088e0fb1afe472f1fff4e4d5574f6eb91dd3a3c0380ea6d3601
```

See also:

* [public-key\_signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
