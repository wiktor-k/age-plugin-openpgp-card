# Age Plugin: OpenPGP Card

[![CI](https://github.com/wiktor-k/age-plugin-openpgp-card/actions/workflows/rust.yml/badge.svg)](https://github.com/wiktor-k/age-plugin-openpgp-card/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/age-plugin-openpgp-card)](https://crates.io/crates/age-plugin-openpgp-card)

This age plugin lets you reuse your OpenPGP Card devices (such as [Yubikeys](https://www.yubico.com/products/yubikey-5-overview/) or [Nitrokeys](https://www.nitrokey.com/products/nitrokeys)) for [age decryption](https://age-encryption.org/).

Why? [OpenPGP Card](https://en.wikipedia.org/wiki/OpenPGP_card), contrary to its name, is just a generic cryptographic device standard.
Most importantly the specification and the real-world devices (e.g. [Yubikeys](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps.html#elliptic-curve-cryptographic-ecc-algorithms) and [Nitrokeys](https://docs.nitrokey.com/nitrokey3/faq#which-algorithms-and-maximum-key-length-are-supported)) support [curve25519](https://en.wikipedia.org/wiki/Curve25519).

This application is a no-moving-parts solution which requires only [`pcsc-lite`](https://github.com/LudovicRousseau/PCSC) on Linux and reuses built-in smartcard services on Windows and macOS. No GnuPG needed, no other OpenPGP software is used or accessed.

If you don't need curve25519 and are using Yubikeys then the [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) provides a more polished experience.

This plugin assumes that you have already provisioned the card.
[`oct admin generate`](https://codeberg.org/openpgp-card/openpgp-card-tools/#generate-keys-on-the-card) may be used to provision the card with a new curve25519 key.
(This is actually how end-to-end tests are implemented. See `scripts/encrypt-and-decrypt.sh`).

## Installation

At this moment the installation from `crates.io` is the only supported method:

```sh
cargo install --locked age-plugin-openpgp-card
```

## Usage

Running the tool directly outputs the public keys and the identity stubs for all connected cards:

```sh
$ age-plugin-openpgp-card | tee identity.txt
# Card ident 0006:15422467
# age1dkfzfyk58yvkf07n32nygkyuqxtnq2am427sy79gjkh6krf96frsucn0me
AGE-PLUGIN-OPENPGP-CARD-1XQCRQD36XY6NGV3JXSMRWAN88PC
```

Note that the public key looks like a regular age ed25519 key.
The stub encodes the card identifier and is mostly irrelevant.
If the stub is lost it may be regenerated - if the key on the card is the same the decryption will succeed.

Any age-compatible tool can be used for encryption:

```sh
$ echo I like strawberries | age -r age1dkfzfyk58yvkf07n32nygkyuqxtnq2am427sy79gjkh6krf96frsucn0me -a > encrypted.age
```

And the identity stubs are required for decryption:

```sh
$ age -d -i identity.txt < encrypted.age
I like strawberries
```

The plugin will ask you for the PIN using built-in plugin protocol (e.g. [`rage`](https://github.com/str4d/rage) would show a pin-entry prompt).

## Tests

This repository contains end-to-end integration tests which run a [virtual Nitrokey card](https://github.com/Nitrokey/opcard-rs), provision it with a new key and then encrypt and decrypt data using `rage`.

## Thanks

The plugin is basically glue code for already existing, awesome libraries and tools:

- [`openpgp-card`](https://crates.io/crates/openpgp-card) which interacts with the smartcards,
- [`age-plugin`](https://crates.io/crates/age-plugin) which provides easy to use framework for writing age plugins,

And, last but not least, [`opcard`](https://github.com/Nitrokey/opcard-rs) which provides us with a virtual card to test that all of this really works!

Thank you very much for all contributors to these projects 🙇‍♂️

## License

This project is licensed under either of:

  - [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0),
  - [MIT license](https://opensource.org/licenses/MIT).

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
