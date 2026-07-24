#!/usr/bin/env python3
"""
check-aep-key.py — Confirm you have a plausibly-correct Account Entropy Pool (AEP)
                   "Backup Key" for a Molly/Signal local-archive backup, and that
                   the backup directory itself is intact.

  NOTE: For a *definitive* answer ("does this key actually decrypt this backup"),
  prefer the Rust tool in ./verify-backup-key/, which links the real Molly
  libsignal fork and does an authenticated decrypt-test. This Python script is a
  no-build FALLBACK: it validates the AEP FORMAT and backup INTEGRITY only, and
  cannot prove the key decrypts the backup.

WHAT THIS CAN AND CANNOT DO
---------------------------
This is an OFFLINE pre-flight check you run BEFORE uninstalling the broken app.

  [CAN]  Validate that your key string is a structurally valid AEP — the exact
         format check Molly's restore screen applies (64 chars, alphanumeric
         after normalizing the display symbols '#'->'O' and '='->'0',
         case-insensitive). If it fails here, Molly will reject it too.

  [CAN]  Validate that the backup directory is a well-formed Molly local archive
         (metadata protobuf parses; main is present and high-entropy; files is a
         clean list of 64-hex attachment digests).

  [CANNOT] Prove this key actually DECRYPTS this backup. That derivation
         (Argon2/HKDF via libsignal) plus your account ACI runs only inside the
         app. The authoritative decrypt-test is the on-device restore itself.

  ==> If BOTH checks below pass, you have the right *kind* of key in valid form
      and an intact backup. That is the strongest confirmation obtainable
      without wiping. The final proof is the restore.

USAGE
-----
  python3 check-aep-key.py /path/to/signal-backup-YYYY-MM-DD-HH-MM-SS
  # then paste your key when prompted (input is hidden)

Derivation reference: core/models-jvm/.../AccountEntropyPool.kt
  LENGTH = 64 ; storage charset [0-9a-zA-Z] ; display map { 'O':'#', '0':'=' }.
"""

import sys
import os
import getpass
import struct

# --- AEP format rules, mirrored from AccountEntropyPool.kt ---------------------
AEP_LENGTH = 64
# CHARACTER_DISPLAY_MAP (storage -> display) from the source; we reverse it to
# turn a user-pasted (display-form) key back into storage form before validating.
DISPLAY_TO_STORAGE = {'#': 'O', '=': '0'}
STORAGE_CHARSET = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def normalize_key(raw: str):
    """Reproduce AccountEntropyPool.parseOrNull: strip display symbols back to
    storage form, drop whitespace/separators, then keep only legal chars."""
    # formatForStorage: reverse the display map
    swapped = "".join(DISPLAY_TO_STORAGE.get(c, c) for c in raw)
    # removeIllegalCharacters: drop anything outside the storage charset
    # (this also removes spaces, dashes, and newlines a user may have pasted)
    stripped = "".join(c for c in swapped if c in STORAGE_CHARSET)
    return stripped


def check_key(raw: str):
    stripped = normalize_key(raw)
    print(f"  raw length entered : {len(raw)}")
    print(f"  usable characters  : {len(stripped)}  (after removing spaces/dashes/symbols)")
    if len(stripped) != AEP_LENGTH:
        print(f"  RESULT: NOT a valid AEP — need exactly {AEP_LENGTH} usable chars, got {len(stripped)}.")
        if len(stripped) == 0:
            print("          (nothing usable — did you paste it?)")
        elif len(stripped) < AEP_LENGTH:
            print("          (too short — likely a partial paste or a different key type,")
            print("           e.g. a 30-digit local-backup passphrase is NOT an AEP.)")
        else:
            print("          (too long — extra characters pasted in?)")
        return False
    print("  RESULT: valid AEP format (64 alphanumeric chars). Molly will accept this at the key screen.")
    return True


# --- Backup directory integrity (offline, no key needed) ----------------------
def read_varint(b, i):
    shift = 0
    val = 0
    while True:
        x = b[i]; i += 1
        val |= (x & 0x7f) << shift
        if not x & 0x80:
            break
        shift += 7
    return val, i


def check_metadata(path):
    data = open(path, "rb").read()
    if not (10 <= len(data) <= 200):
        print(f"  metadata: unexpected size {len(data)} (expected a small protobuf ~36 bytes)")
        return False
    try:
        i = 0
        fields = {}
        while i < len(data):
            tag, i = read_varint(data, i)
            field, wt = tag >> 3, tag & 7
            if wt == 0:
                v, i = read_varint(data, i); fields[field] = ("varint", v)
            elif wt == 2:
                ln, i = read_varint(data, i); fields[field] = ("bytes", ln); i += ln
            else:
                print(f"  metadata: unexpected wiretype {wt}"); return False
        # Expect field 1 = version varint, field 2 = 32-byte key material
        ok = fields.get(1, (None,))[0] == "varint" and fields.get(2) == ("bytes", 32)
        print(f"  metadata: parsed fields={ { k: v[0] for k, v in fields.items() } } "
              f"-> {'OK' if ok else 'UNEXPECTED SHAPE'}")
        return ok
    except Exception as e:
        print(f"  metadata: parse error ({e})")
        return False


def shannon_entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    from math import log2
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    n = len(sample)
    return -sum((c / n) * log2(c / n) for c in counts if c)


def check_main(path):
    size = os.path.getsize(path)
    if size < 1024:
        print(f"  main: suspiciously small ({size} bytes) — possibly truncated")
        return False
    with open(path, "rb") as f:
        sample = f.read(65536)
    ent = shannon_entropy(sample)
    ok = ent > 7.5  # encrypted data is near 8.0 bits/byte
    print(f"  main: {size:,} bytes, entropy {ent:.2f}/8.0 bits "
          f"-> {'OK (encrypted archive)' if ok else 'LOW ENTROPY — not encrypted data?'}")
    return ok


def check_files(path):
    valid = 0
    total = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            s = line.strip().strip("@B")
            if not s:
                continue
            total += 1
            if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
                valid += 1
    ok = total > 0 and valid == total
    print(f"  files: {valid}/{total} well-formed 64-hex attachment digests "
          f"-> {'OK' if ok else 'SOME MALFORMED'}")
    return ok


def check_backup_dir(path):
    print(f"\n[2] Backup integrity: {path}")
    if not os.path.isdir(path):
        print("  ERROR: not a directory. A Molly local archive is a FOLDER containing")
        print("         'main', 'files', and 'metadata'. Point me at that folder.")
        return False
    results = []
    for name, fn in (("metadata", check_metadata), ("main", check_main), ("files", check_files)):
        p = os.path.join(path, name)
        if not os.path.exists(p):
            print(f"  ERROR: missing '{name}' — this is not a complete local archive.")
            results.append(False)
            continue
        results.append(fn(p))
    return all(results)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        print("ERROR: pass the backup directory path.\n"
              "  python3 check-aep-key.py /path/to/signal-backup-YYYY-MM-DD-HH-MM-SS")
        sys.exit(2)

    backup_dir = sys.argv[1]

    print("=" * 70)
    print("Molly AEP / Backup Key pre-flight check")
    print("=" * 70)
    print("This confirms your key's FORMAT and your backup's INTEGRITY offline.")
    print("It cannot prove the key decrypts the backup — only the on-device")
    print("restore can do that. Run this BEFORE you uninstall the broken app.\n")

    print("[1] Key format check")
    print("    Paste your Backup Key / Account Entropy Pool (input hidden).")
    print("    Spaces, dashes, and the display symbols # and = are handled.")
    try:
        raw = getpass.getpass("    Key: ")
    except (EOFError, KeyboardInterrupt):
        print("\n  (no key entered)")
        raw = ""
    key_ok = check_key(raw) if raw else False

    dir_ok = check_backup_dir(backup_dir)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print(f"  Key format valid   : {'YES' if key_ok else 'NO'}")
    print(f"  Backup intact       : {'YES' if dir_ok else 'NO'}")
    if key_ok and dir_ok:
        print("\n  ==> Both checks pass. You have a valid-form AEP and an intact backup.")
        print("      This is the strongest confirmation possible without wiping.")
        print("      Next: keep the key safe, copy the backup folder to the phone,")
        print("      then reinstall Molly-FOSS and restore via registration ->")
        print("      'Restore from local backup'. The restore is the final proof.")
    else:
        print("\n  ==> Do NOT uninstall the broken app yet. Resolve the NO(s) above first:")
        if not key_ok:
            print("      - Key: locate the 64-char Backup Key you saved when enabling backups.")
        if not dir_ok:
            print("      - Backup: re-copy the full folder; ensure main/files/metadata present.")
    print("=" * 70)
    sys.exit(0 if (key_ok and dir_ok) else 1)


if __name__ == "__main__":
    main()
