//! verify-backup-key — Does an AEP + ACI actually open THIS Molly local backup?
//!
//! This is a real decrypt-test, not a format check. It links the actual Molly
//! libsignal fork (tag v0.96.3-1, matching the app's pinned libsignal-client)
//! so the key derivation is byte-for-byte what the app does — no guessed crypto.
//!
//! What it reproduces (see LocalArchiver.kt `getBackupId` / `decryptBackupId`):
//!
//!   1. AEP -> BackupKey                (BackupKey::derive_from_account_entropy_pool)
//!   2. BackupKey -> metadata_key        (derive_local_backup_metadata_key, HKDF)
//!   3. Decrypt the `metadata` frame's encryptedId with AES-256-CTR(metadata_key, iv, ctr=0)
//!      -> the STORED backup id that the app wrote at export time.
//!   4. BackupKey + ACI -> EXPECTED backup id   (derive_backup_id, HKDF over ACI)
//!   5. If STORED == EXPECTED, the AEP *and* ACI are correct for this backup.
//!
//! Why the equality is authoritative: the metadata_key depends only on the AEP,
//! and the expected id depends on AEP+ACI. A wrong AEP yields a wrong CTR
//! keystream (garbage stored id) AND a wrong expected id; a wrong ACI yields a
//! wrong expected id. Only the true (AEP, ACI) pair makes the two sides agree.
//!
//! Usage:
//!   verify-backup-key <backup-dir> <ACI-uuid>
//!   # AEP is read from stdin / prompt (never a CLI arg, so it stays out of shell history)

use std::io::Read;
use std::str::FromStr;

use aes::cipher::{KeyIvInit, StreamCipher};
use libsignal_account_keys::{AccountEntropyPool, BackupKey};
use libsignal_core::Aci;
use uuid::Uuid;

// AES-256 in 32-bit big-endian counter mode — this is exactly Aes256Ctr32 from
// libsignal (rust/crypto/src/aes_ctr.rs): a 12-byte nonce placed in the high 12
// bytes of the 16-byte counter block, with a 32-bit BE counter starting at 0.
type Aes256Ctr32BE = ctr::Ctr32BE<aes::Aes256>;

const METADATA_KEY_LEN: usize = 32;

fn die(msg: &str) -> ! {
    eprintln!("ERROR: {msg}");
    std::process::exit(2);
}

/// Minimal protobuf reader for the tiny `metadata` file:
///   message Metadata {
///     uint32 version = 1;                 // wire type 0 (varint)
///     EncryptedBackupId backup_id = 2;    // wire type 2 (len-delimited)
///   }
///   message EncryptedBackupId { bytes iv = 1; bytes encrypted_id = 2; }
fn read_varint(b: &[u8], i: &mut usize) -> u64 {
    let mut shift = 0u32;
    let mut val = 0u64;
    loop {
        let x = b[*i];
        *i += 1;
        val |= ((x & 0x7f) as u64) << shift;
        if x & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    val
}

/// Returns (iv, encrypted_id) from the metadata protobuf.
fn parse_metadata(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut i = 0usize;
    let mut version: Option<u64> = None;
    let mut backup_id_bytes: Option<Vec<u8>> = None;
    while i < data.len() {
        let tag = read_varint(data, &mut i);
        let (field, wt) = (tag >> 3, tag & 7);
        match (field, wt) {
            (1, 0) => version = Some(read_varint(data, &mut i)),
            (2, 2) => {
                let len = read_varint(data, &mut i) as usize;
                backup_id_bytes = Some(data[i..i + len].to_vec());
                i += len;
            }
            (_, 0) => {
                read_varint(data, &mut i);
            }
            (_, 2) => {
                let len = read_varint(data, &mut i) as usize;
                i += len;
            }
            _ => die("unexpected wiretype in metadata protobuf"),
        }
    }
    if version.is_none() {
        die("metadata: no version field — not a Molly local-archive metadata file");
    }
    let inner = backup_id_bytes
        .unwrap_or_else(|| die("metadata: missing EncryptedBackupId (field 2)"));

    // parse EncryptedBackupId { iv=1 bytes, encrypted_id=2 bytes }
    let mut j = 0usize;
    let mut iv: Option<Vec<u8>> = None;
    let mut enc: Option<Vec<u8>> = None;
    while j < inner.len() {
        let tag = read_varint(&inner, &mut j);
        let (field, wt) = (tag >> 3, tag & 7);
        if wt != 2 {
            die("EncryptedBackupId: unexpected wiretype");
        }
        let len = read_varint(&inner, &mut j) as usize;
        let val = inner[j..j + len].to_vec();
        j += len;
        match field {
            1 => iv = Some(val),
            2 => enc = Some(val),
            _ => {}
        }
    }
    (
        iv.unwrap_or_else(|| die("EncryptedBackupId: missing iv")),
        enc.unwrap_or_else(|| die("EncryptedBackupId: missing encrypted_id")),
    )
}

fn normalize_aep(raw: &str) -> String {
    // Molly displays the AEP with 'O'->'#' and '0'->'=' swaps and in groups;
    // reverse those and strip anything that isn't a storage char, then lowercase.
    raw.chars()
        .map(|c| match c {
            '#' => 'O',
            '=' => '0',
            other => other,
        })
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

/// Reproduces libsignal's own known-answer vector (account-keys/src/backup.rs
/// tests) to prove the derivation wired here is byte-for-byte faithful before we
/// trust it on a real backup. AEP -> BackupKey -> derive_backup_id(ACI).
fn self_test() -> ! {
    const AEP: &str = "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l";
    let aci_bytes = hex::decode("659aa5f4a28dfcc11ea1b997537a3d95").unwrap();
    let expected_id = "8a624fbc45379043f39f1391cddc5fe8";
    let expected_key = "ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985";

    let aep = AccountEntropyPool::from_str(AEP).expect("valid test AEP");
    let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
    let aci = Aci::from_uuid_bytes(aci_bytes.try_into().unwrap());
    let id = backup_key.derive_backup_id(&aci);

    let got_key = hex::encode(backup_key.0);
    let got_id = hex::encode(id.0);
    println!("self-test backup key : {got_key}");
    println!("self-test backup id  : {got_id}");
    let ok = got_key == expected_key && got_id == expected_id;
    if ok {
        println!("✅ self-test PASSED — derivation matches libsignal's known-answer vector.");
        std::process::exit(0);
    } else {
        println!("❌ self-test FAILED — derivation does NOT match. Do not trust results.");
        println!("   expected key {expected_key}");
        println!("   expected id  {expected_id}");
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--self-test" {
        self_test();
    }
    if args.len() != 3 {
        eprintln!("Usage: {} <backup-dir> <ACI-uuid>", args[0]);
        eprintln!("  The AEP / Backup Key is read from stdin (hidden), not the command line.");
        std::process::exit(2);
    }
    let backup_dir = &args[1];
    let aci_str = &args[2];

    // --- read metadata frame ---
    let meta_path = format!("{backup_dir}/metadata");
    let main_path = format!("{backup_dir}/main");
    let meta = std::fs::read(&meta_path)
        .unwrap_or_else(|e| die(&format!("cannot read {meta_path}: {e}")));
    if std::fs::metadata(&main_path).is_err() {
        die(&format!("missing {main_path} — not a complete local archive"));
    }
    let (iv, encrypted_id) = parse_metadata(&meta);
    if iv.len() != Aes256Ctr32BE::iv_size() {
        // Ctr32BE nonce block is 16 bytes; our 12-byte nonce needs a 4-byte zero counter appended.
    }

    // --- parse ACI ---
    let aci_uuid = Uuid::from_str(aci_str.trim())
        .unwrap_or_else(|e| die(&format!("invalid ACI uuid '{aci_str}': {e}")));
    let aci = Aci::from(aci_uuid);

    // --- read AEP from stdin (prompt) ---
    eprint!("Paste your Backup Key / Account Entropy Pool, then press Enter:\n> ");
    use std::io::Write as _;
    std::io::stderr().flush().ok();
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .unwrap_or_else(|e| die(&format!("failed reading key from stdin: {e}")));
    let aep_norm = normalize_aep(&raw);
    if aep_norm.len() != 64 {
        die(&format!(
            "key is not a valid AEP: got {} usable chars, need exactly 64 \
             (a 30-digit local passphrase is NOT an AEP)",
            aep_norm.len()
        ));
    }
    let aep = AccountEntropyPool::from_str(&aep_norm)
        .unwrap_or_else(|_| die("key failed AccountEntropyPool validation (bad character set)"));

    // --- THE REAL DERIVATION (libsignal) ---
    let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);
    let metadata_key = backup_key.derive_local_backup_metadata_key();
    let expected_id = backup_key.derive_backup_id(&aci);

    // --- decrypt the stored backup id with AES-256-CTR(metadata_key, iv, ctr=0) ---
    let mut nonce_block = [0u8; 16];
    if iv.len() != 12 {
        die(&format!("metadata iv length {} != 12", iv.len()));
    }
    nonce_block[..12].copy_from_slice(&iv); // low 4 bytes = BE counter 0
    let mut cipher = Aes256Ctr32BE::new(
        (&metadata_key as &[u8; METADATA_KEY_LEN]).into(),
        (&nonce_block).into(),
    );
    let mut stored_id = encrypted_id.clone();
    cipher.apply_keystream(&mut stored_id);

    // --- compare ---
    let expected_bytes: &[u8] = &expected_id.0;
    let matched = stored_id.as_slice() == expected_bytes;

    println!("─────────────────────────────────────────────────────────");
    println!(" backup dir : {backup_dir}");
    println!(" ACI        : {aci_uuid}");
    println!(" expected id: {}", hex::encode(expected_bytes));
    println!(" decrypted  : {}", hex::encode(&stored_id));
    println!("─────────────────────────────────────────────────────────");
    if matched {
        println!(" ✅ MATCH — this AEP and ACI correctly open this backup.");
        println!("    Safe to proceed: keep this key, then restore on device.");
        std::process::exit(0);
    } else {
        println!(" ❌ NO MATCH — this (AEP, ACI) pair does NOT open this backup.");
        println!("    Either the key is wrong, or the ACI is wrong. Do NOT wipe.");
        std::process::exit(1);
    }
}

// Small helper so the iv-size guard above compiles regardless of trait import.
trait IvSize {
    fn iv_size() -> usize;
}
impl IvSize for Aes256Ctr32BE {
    fn iv_size() -> usize {
        16
    }
}
