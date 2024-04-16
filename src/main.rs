use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::{crypto_data::PublicKeyMaterial, Card};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};

use std::collections::HashMap;
use std::io;

use age_core::{
    format::FILE_KEY_BYTES,
    primitives::{aead_decrypt, aead_encrypt, hkdf},
    secrecy::{ExposeSecret, SecretString},
};

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const SECRET_KEY_PREFIX: &str = "age-secret-key-";
const PUBLIC_KEY_PREFIX: &str = "age";

pub const X25519_RECIPIENT_TAG: &str = "X25519";
const X25519_RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

pub const EPK_LEN_BYTES: usize = 32;
pub const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;
struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
    }
}

struct IdentityPlugin;

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
impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        eprintln!("add_identity: {index} {plugin_name} {bytes:?}");
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let stanza = &files[0][0];
        eprintln!("stanza {stanza:?}");
        if stanza.tag != X25519_RECIPIENT_TAG {
            panic!("return None;");
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#x25519-recipient-stanza
        let ephemeral_share = match &stanza.args[..] {
            [arg] => match base64_arg::<_, EPK_LEN_BYTES, 33>(arg) {
                Some(ephemeral_share) => ephemeral_share,
                None => panic!("return Some(Err(DecryptError::InvalidHeader)),"),
            },
            _ => panic!("return Some(Err(DecryptError::InvalidHeader)),"),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            panic!("return Some(Err(DecryptError::InvalidHeader));");
        }

        let epk: PublicKey = ephemeral_share.into();
        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = stanza.body[..]
            .try_into()
            .expect("Length should have been checked above");

        //        let pk: PublicKey = (&self.0).into();
        let backend = PcscBackend::cards(None)
            .expect("cards")
            .into_iter()
            .next()
            .expect("one card");
        let mut card = Card::new(backend.expect("backend")).expect("card");
        let mut tx = card.transaction().expect("tx");
        let pk: Vec<u8> = if let PublicKeyMaterial::E(ecc) = tx
            .public_key(openpgp_card::KeyType::Decryption)
            .expect("pk")
        {
            ecc.data().into()
        } else {
            panic!("not ecc key");
        };
        tx.verify_pw1_user(
            callbacks
                .request_secret("plz unlock")?
                .expect("secret")
                .expose_secret()
                .as_bytes(),
        )
        .expect("verify to work");
        let shared_secret = tx
            .decipher(openpgp_card::crypto_data::Cryptogram::ECDH(
                &ephemeral_share,
            ))
            .expect("decipher to work");
        //let shared_secret = "test"; //self.0.diffie_hellman(&epk);
        // Replace with `SharedSecret::was_contributory` once x25519-dalek supports newer
        // zeroize (https://github.com/dalek-cryptography/x25519-dalek/issues/74#issuecomment-1159481280).
        if shared_secret
            .iter()
            .fold(0, |acc, b| acc | b)
            .ct_eq(&0)
            .into()
        {
            panic!("return Some(Err(DecryptError::InvalidHeader));");
        }

        let mut salt = [0; 64];
        salt[..32].copy_from_slice(epk.as_bytes());
        salt[32..].copy_from_slice(&pk[..]);

        let enc_key = hkdf(&salt, X25519_RECIPIENT_KEY_LABEL, &shared_secret);

        // A failure to decrypt is non-fatal (we try to decrypt the recipient
        // stanza with other X25519 keys), because we cannot tell which key
        // matches a particular stanza.
        let result = aead_decrypt(&enc_key, FILE_KEY_BYTES, &encrypted_file_key)
            .ok()
            .map(|mut pt| {
                // It's ours!
                let file_key: [u8; FILE_KEY_BYTES] = pt[..].try_into().unwrap();
                //pt.zeroize();
                Ok(FileKey::from(file_key))
            })
            .unwrap();

        let mut map = HashMap::new();
        map.insert(0, result);
        Ok(map) //result
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
        // The plugin was started by an age client; run the state machine.
        return Ok(run_state_machine(
            &state_machine,
            Some(|| RecipientPlugin),
            Some(|| IdentityPlugin),
        )?);
    }
    use bech32::{ToBase32, Variant};
    const IDENTITY_PREFIX: &str = "age-plugin-openpgp-card-";

    const PUBLIC_KEY_PREFIX: &str = "age";

    for backend in PcscBackend::cards(None)? {
        let mut card = Card::new(backend?)?;
        let mut tx = card.transaction()?;
        //tx.application_related_data()?;
        //tx.verify_pw1_user(&"12345".as_bytes())?;
        //tx.decipher(openpgp_card::crypto_data::Cryptogram::ECDH())
        //
        if let PublicKeyMaterial::E(ecc) = tx.public_key(openpgp_card::KeyType::Decryption)? {
            eprintln!(
                "# {}",
                bech32::encode(PUBLIC_KEY_PREFIX, ecc.data().to_base32(), Variant::Bech32)
                    .expect("HRP is valid")
            );

            eprintln!(
                "Encoded: {}",
                bech32::encode(IDENTITY_PREFIX, &[1, 2, 3].to_base32(), Variant::Bech32,)
                    .expect("bech to work")
                    .to_uppercase()
            );
        }
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.

    Ok(())
}

fn decrypt() -> Result<(), Box<dyn std::error::Error>> {
    for backend in PcscBackend::cards(None)? {
        let mut card = Card::new(backend?)?;
        let mut tx = card.transaction()?;
        //tx.application_related_data()?;
        tx.verify_pw1_user(&"12345".as_bytes())?;
        //tx.decipher(openpgp_card::crypto_data::Cryptogram::ECDH())
        //
    }
    Ok(())
}
