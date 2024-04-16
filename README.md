# Age Plugin: OpenPGP Card

This age plugin allows you to reuse your OpenPGP Card devices (such as Yubikeys or Nitrokeys) for [age decryption](https://age-encryption.org/).

Why? [OpenPGP Card](https://en.wikipedia.org/wiki/OpenPGP_card), contrary to its name, is just a generic cryptographic device but most importantly the spec and the real-world devices (e.g. Yubikeys) in the wild [support ed25519](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps.html#elliptic-curve-cryptographic-ecc-algorithms).

If you don't need ed25519 [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) provides a more polished experience.

This plugin assumes that you have already provisioned the card.
[`oct admin generate`](https://codeberg.org/openpgp-card/openpgp-card-tools/#generate-keys-on-the-card) may be used to provision the card with a new ed25519 key.

## Usage

Running the tool directly outputs public keys and identity stubs for all connected cards:

```sh
$ age-plugin-openpgp-card | tee identity.txt
# Card ident 0006:15422467
# age1dkfzfyk58yvkf07n32nygkyuqxtnq2am427sy79gjkh6krf96frsucn0me
AGE-PLUGIN-OPENPGP-CARD-1XQCRQD36XY6NGV3JXSMRWAN88PC
```

Note that the public key looks like a regular age ed25519 key.
The stub encodes the card identifier and is mostly irrelevant.

Any age-compatible tool can be used for encryption:

```sh
$ echo I like strawberries | rage -r age1dkfzfyk58yvkf07n32nygkyuqxtnq2am427sy79gjkh6krf96frsucn0me -a > encrypted.age
```

And the identity stubs are required for decryption:

```sh
$ rage -d -i identity.txt < encrypted.age
I like strawberries
```

The plugin will ask you for the PIN using built-in plugin protocol (this would usually show a pin-entry prompt).

## License

This project is licensed under either of:

  - [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0),
  - [MIT license](https://opensource.org/licenses/MIT).

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
