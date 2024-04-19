#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::io;

use age_core::{
    format::FILE_KEY_BYTES,
    primitives::{aead_decrypt, hkdf},
    secrecy::ExposeSecret,
};
use age_core::{
    format::{FileKey, Stanza},
    secrecy::Zeroize as _,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use bech32::{ToBase32, Variant};
use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::{crypto_data::PublicKeyMaterial, Card};
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const IDENTITY_PREFIX: &str = "age-plugin-openpgp-card-";
const PUBLIC_KEY_PREFIX: &str = "age";
const PLUGIN_NAME: &str = "openpgp-card";

pub const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub const EPK_LEN_BYTES: usize = 32;
pub const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;
struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        _file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
    }
}

struct CardStub {
    ident: String,
}

struct IdentityPlugin {
    cards: Vec<CardStub>,
}

use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
pub(crate) fn base64_arg<A: AsRef<[u8]>, const N: usize, const B: usize>(
    arg: &A,
) -> Option<[u8; N]> {
    if N > B {
        return None;
    }

    let mut buf = [0; B];
    match BASE64_STANDARD_NO_PAD.decode_slice(arg, buf.as_mut()) {
        Ok(n) if n == N => Some(buf[..N].try_into().unwrap()),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
enum DecryptError {
    #[error("Invalid header")]
    InvalidHeader,
    #[error("Card does not contain ECC key")]
    NonEccCard,
}

impl IdentityPlugin {
    fn get_card(ident: &str) -> Result<Option<Card>, Box<dyn std::error::Error>> {
        for backend in PcscBackend::cards(None)? {
            let mut card = Card::new(backend?)?;
            let tx = card.transaction()?;
            if ident == tx.application_identifier()?.ident() {
                drop(tx);
                return Ok(Some(card));
            }
        }
        Ok(None)
    }

    fn unwrap_stanza(
        &mut self,
        stanza: &Stanza,
        callbacks: &mut impl Callbacks<identity::Error>,
    ) -> Result<Option<FileKey>, Box<dyn std::error::Error>> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            return Err(std::io::Error::other("bad stanza tag").into());
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#x25519-recipient-stanza
        let ephemeral_share = match &stanza.args[..] {
            [arg] => match base64_arg::<_, EPK_LEN_BYTES, 33>(arg) {
                Some(ephemeral_share) => ephemeral_share,
                None => return Err(DecryptError::InvalidHeader.into()),
            },
            _ => return Err(DecryptError::InvalidHeader.into()),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Err(DecryptError::InvalidHeader.into());
        }

        let epk: PublicKey = ephemeral_share.into();
        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = stanza.body[..]
            .try_into()
            .expect("Length should have been checked above");

        'cards: for card in self.cards.iter() {
            let mut card = loop {
                let car = Self::get_card(&card.ident)?;
                if let Some(card) = car {
                    break card;
                } else {
                    let res = callbacks.confirm(
                        &format!("Please insert card {}", card.ident),
                        "OK",
                        None,
                    )??;
                    if !res {
                        continue 'cards;
                    };
                }
            };
            let mut tx = card.transaction()?;
            let ident = tx.application_identifier()?.ident();
            if !self.cards.iter().any(|stub| stub.ident == ident) {
                // it's not a card we have the identity for
                continue;
            }
            let pk: Vec<u8> = if let PublicKeyMaterial::E(ecc) =
                tx.public_key(openpgp_card::KeyType::Decryption)?
            {
                ecc.data().into()
            } else {
                return Err(DecryptError::NonEccCard.into());
            };
            tx.verify_pw1_user(
                callbacks
                    .request_secret(&format!("Unlock card {ident}"))??
                    .expose_secret()
                    .as_bytes(),
            )?;
            let shared_secret = tx.decipher(openpgp_card::crypto_data::Cryptogram::ECDH(
                &ephemeral_share,
            ))?;
            if shared_secret
                .iter()
                .fold(0, |acc, b| acc | b)
                .ct_eq(&0)
                .into()
            {
                return Err(DecryptError::InvalidHeader.into());
            }

            let mut salt = [0; 64];
            salt[..32].copy_from_slice(epk.as_bytes());
            salt[32..].copy_from_slice(&pk[..]);

            let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);

            // A failure to decrypt is non-fatal (we try to decrypt the recipient
            // stanza with other X25519 keys), because we cannot tell which key
            // matches a particular stanza.
            if let Some(result) = aead_decrypt(&enc_key, FILE_KEY_BYTES, &encrypted_file_key)
                .ok()
                .map(|mut pt| {
                    // It's ours!
                    let file_key: [u8; FILE_KEY_BYTES] = pt[..].try_into().unwrap();
                    pt.zeroize();
                    FileKey::from(file_key)
                })
            {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name == PLUGIN_NAME {
            self.cards.push(CardStub {
                ident: String::from_utf8_lossy(bytes).to_string(),
            });
            Ok(())
        } else {
            Err(identity::Error::Identity {
                index,
                message: "invalid recipient".into(),
            })
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut file_keys = HashMap::with_capacity(files.len());
        for (file_index, stanzas) in files.iter().enumerate() {
            for (stanza_index, stanza) in stanzas.iter().enumerate() {
                match self.unwrap_stanza(stanza, &mut callbacks).map_err(|e| {
                    vec![identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: e.to_string(),
                    }]
                }) {
                    Ok(Some(file_key)) => {
                        file_keys.entry(file_index).or_insert(Ok(file_key));
                    }

                    Err(error) => {
                        file_keys.entry(file_index).or_insert(Err(error));
                    }
                    _ => {}
                }
            }
        }

        Ok(file_keys)
    }
}

#[derive(Debug, Parser)]
struct PluginOptions {
    #[arg(help = "run the given age plugin state machine", long)]
    age_plugin: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = PluginOptions::parse();

    if let Some(state_machine) = opts.age_plugin {
        return Ok(run_state_machine(
            &state_machine,
            Some(|| RecipientPlugin),
            Some(|| IdentityPlugin { cards: vec![] }),
        )?);
    }

    for backend in PcscBackend::cards(None)? {
        let mut card = Card::new(backend?)?;
        let mut tx = card.transaction()?;
        if let PublicKeyMaterial::E(ecc) = tx.public_key(openpgp_card::KeyType::Decryption)? {
            let ident = tx.application_identifier()?.ident();
            println!("# Card ident {}", ident);
            println!(
                "# {}",
                bech32::encode(PUBLIC_KEY_PREFIX, ecc.data().to_base32(), Variant::Bech32)?
            );

            println!(
                "{}",
                bech32::encode(IDENTITY_PREFIX, ident.to_base32(), Variant::Bech32,)?
                    .to_uppercase()
            );
            println!();
        }
    }

    Ok(())
}
