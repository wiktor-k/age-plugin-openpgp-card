#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::io;

use age_core::{
    format::FILE_KEY_BYTES,
    primitives::{aead_decrypt, hkdf},
};
use age_core::{
    format::{FileKey, Stanza},
    secrecy::zeroize::Zeroize as _,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    run_state_machine, Callbacks, PluginHandler,
};
use bech32::{Bech32, Hrp};
use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::{
    ocard::{
        crypto::{Cryptogram, PublicKeyMaterial},
        KeyType::Decryption,
    },
    state::{Open, Transaction},
    Card,
};
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const IDENTITY_PREFIX: Hrp = Hrp::parse_unchecked("age-plugin-openpgp-card-");
const PUBLIC_KEY_PREFIX: Hrp = Hrp::parse_unchecked("age");
const PLUGIN_NAME: &str = "openpgp-card";

pub const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub const EPK_LEN_BYTES: usize = 32;
pub const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

impl PluginHandler for IdentityPlugin {
    type RecipientV1 = std::convert::Infallible;

    type IdentityV1 = IdentityPlugin;

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(self)
    }
}

type FileKeys = HashMap<usize, Result<FileKey, Vec<identity::Error>>>;

#[derive(Debug)]
struct CardStub {
    /// Index of the identity, as assigned by the age client.
    index: usize,
    ident: String,
}

#[derive(Debug, Default)]
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
        Ok(n) if n == N => buf[..N].try_into().ok(),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
enum DecryptError {
    #[error("Invalid header")]
    InvalidHeader,
}

impl IdentityPlugin {
    fn get_card(ident: &str) -> Result<Option<Card<Open>>, Box<dyn std::error::Error>> {
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

    fn unwrap_stanza<'a>(
        tx: &mut Card<Transaction<'a>>,
        ident: &str,
        pk: &[u8; 32],
        stanza: &Stanza,
        callbacks: &mut impl Callbacks<identity::Error>,
    ) -> Result<Option<FileKey>, Box<dyn std::error::Error>> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            // Stanzas for other recipient types are not ours: ignore them.
            return Ok(None);
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
        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = stanza.body[..]
            .try_into()
            .map_err(|_| DecryptError::InvalidHeader)?;

        let epk: PublicKey = ephemeral_share.into();

        if let Ok(Some(uif)) = tx.user_interaction_flag(Decryption) {
            if uif.touch_policy().touch_required() {
                callbacks.message(&format!("Touch your card {ident} now to decrypt."))??;
            }
        };

        let shared_secret = tx.card().decipher(Cryptogram::ECDH(&ephemeral_share))?;
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
        salt[32..].copy_from_slice(pk);

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);

        // A failure to decrypt is non-fatal (we try to decrypt the recipient
        // stanza with other X25519 keys), because we cannot tell which key
        // matches a particular stanza.
        if let Ok(mut pt) = aead_decrypt(&enc_key, FILE_KEY_BYTES, &encrypted_file_key) {
            // It's ours!
            let file_key: Result<[u8; FILE_KEY_BYTES], _> = pt[..].try_into();
            pt.zeroize();
            let file_key = file_key.map_err(|_| DecryptError::InvalidHeader)?;
            return Ok(Some(FileKey::new(Box::new(file_key))));
        }

        Ok(None)
    }

    /// Tries to unwrap the file keys using a single card.
    ///
    /// Keys are added to `file_keys`; files that already have a key are not
    /// tried again. The card is skipped if the user declined to insert it, or
    /// if it does not hold an X25519 decryption key.
    fn unwrap_with_card(
        card_stub: &CardStub,
        files: &[Vec<Stanza>],
        file_keys: &mut FileKeys,
        callbacks: &mut impl Callbacks<identity::Error>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ident = card_stub.ident.as_str();
        let mut card = loop {
            if let Some(card) = Self::get_card(ident)? {
                break card;
            }
            if !callbacks.confirm(&format!("Please insert card {ident}"), "OK", None)?? {
                return Ok(());
            }
        };

        let mut tx = card.transaction()?;
        let pk: [u8; 32] = match tx.public_key_material(Decryption)? {
            PublicKeyMaterial::E(ecc) => match ecc.data().try_into() {
                Ok(pk) => pk,
                Err(_) => return Ok(()),
            },
            _ => return Ok(()),
        };

        // Prefer the reader's (or device's) own PIN entry: the PIN then never
        // passes through the host, where a keylogger could record it.
        if tx.feature_pinpad_verify() {
            callbacks.message(&format!("Enter the PIN of card {ident} on its pin pad"))??;
            tx.verify_user_pinpad(&|| {})?;
        } else {
            tx.verify_user_pin(callbacks.request_secret(&format!("Unlock card {ident}"))??)?;
        }

        for (file_index, stanzas) in files.iter().enumerate() {
            if file_keys.contains_key(&file_index) {
                continue;
            }
            for stanza in stanzas {
                // Stanzas that fail to unwrap are skipped: they may be addressed
                // to other recipients.
                if let Ok(Some(file_key)) =
                    Self::unwrap_stanza(&mut tx, ident, &pk, stanza, callbacks)
                {
                    file_keys.insert(file_index, Ok(file_key));
                    // The remaining stanzas would only cost further card
                    // operations (and touches).
                    break;
                }
            }
        }

        Ok(())
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
                index,
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
    ) -> io::Result<FileKeys> {
        let mut file_keys = FileKeys::with_capacity(files.len());
        let mut errors = vec![];
        for card_stub in &self.cards {
            if file_keys.len() == files.len() {
                // Nothing left to unwrap: do not bother the user with more cards.
                break;
            }
            if let Err(e) =
                Self::unwrap_with_card(card_stub, &files, &mut file_keys, &mut callbacks)
            {
                // Remember the failure and give the remaining cards a chance.
                errors.push(identity::Error::Identity {
                    index: card_stub.index,
                    message: format!("card {}: {e}", card_stub.ident),
                });
            }
        }

        // Report card failures to the age client only if they may be the reason
        // a file could not be unwrapped. Identity errors are not tied to a file,
        // so they are attached to the first file that is still missing its key.
        if !errors.is_empty() {
            if let Some(file_index) = (0..files.len()).find(|i| !file_keys.contains_key(i)) {
                file_keys.insert(file_index, Err(errors));
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
            IdentityPlugin::default(),
        )?);
    }

    for backend in PcscBackend::cards(None)? {
        let mut card = Card::new(backend?)?;
        let mut tx = card.transaction()?;
        if let PublicKeyMaterial::E(ecc) = tx.public_key_material(Decryption)? {
            let ident = tx.application_identifier()?.ident();
            println!("# Card ident {}", ident);
            println!(
                "# {}",
                bech32::encode::<Bech32>(PUBLIC_KEY_PREFIX, ecc.data())?
            );

            println!(
                "{}",
                bech32::encode::<Bech32>(IDENTITY_PREFIX, ident.as_bytes())?.to_uppercase()
            );
            println!();
        }
    }

    Ok(())
}
