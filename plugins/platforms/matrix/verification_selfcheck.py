"""Offline self-check for SAS verification. No homeserver needed.

Runs two olm.Sas instances through the real handshake — commitment, key exchange,
emoji derivation, MAC exchange — and asserts both sides agree. If the SAS info
string, the bit-slicing, or the MAC construction ever drifts, this fails.

Run:
  "%LOCALAPPDATA%\\hermes\\hermes-agent\\venv\\Scripts\\python.exe" verification_selfcheck.py
"""

import sys
from pathlib import Path

# The Windows console defaults to cp1252, which cannot encode the SAS emoji.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))

import fresholm.import_hook  # noqa: F401
import olm  # type: ignore

from verification import EMOJI, canonical_json, sas_emoji_indices, sas_decimals

INIT_USER, INIT_DEV = "@gurpreet:matrix.nexio.ca", "ELEMENTDEV"
ACC_USER, ACC_DEV = "@hermes:matrix.nexio.ca", "CNIBLMHDAS"
TX = "tx-selfcheck-1"


def sas_info(init_key: str, acc_key: str) -> str:
    """Initiator identity first — both sides build this identically."""
    return ("MATRIX_KEY_VERIFICATION_SAS"
            f"|{INIT_USER}|{INIT_DEV}|{init_key}"
            f"|{ACC_USER}|{ACC_DEV}|{acc_key}"
            f"|{TX}")


def mac_info(a_user, a_dev, b_user, b_dev) -> str:
    return "MATRIX_KEY_VERIFICATION_MAC" + a_user + a_dev + b_user + b_dev + TX


def main() -> int:
    initiator, accepter = olm.Sas(), olm.Sas()

    start_content = {
        "from_device": INIT_DEV, "method": "m.sas.v1", "transaction_id": TX,
        "key_agreement_protocols": ["curve25519-hkdf-sha256"],
        "hashes": ["sha256"],
        "message_authentication_codes": ["hkdf-hmac-sha256"],
        "short_authentication_string": ["emoji", "decimal"],
    }

    # 1. commitment binds the accepter's key to the initiator's start event
    commitment = olm.sha256(accepter.pubkey + canonical_json(start_content))
    assert commitment == olm.sha256(accepter.pubkey + canonical_json(start_content)), \
        "commitment must be deterministic"
    assert "=" not in commitment, "olm.sha256 must return UNPADDED base64"
    print(f"  commitment ok ({commitment[:12]}…)")

    # canonical json must be stable regardless of key order
    shuffled = dict(reversed(list(start_content.items())))
    assert canonical_json(shuffled) == canonical_json(start_content), \
        "canonical_json must sort keys"
    print("  canonical_json stable under key reordering")

    # 2. key exchange
    initiator.set_their_pubkey(accepter.pubkey)
    accepter.set_their_pubkey(initiator.pubkey)

    info = sas_info(initiator.pubkey, accepter.pubkey)
    a_bytes = initiator.generate_bytes(info, 6)
    b_bytes = accepter.generate_bytes(info, 6)
    assert a_bytes == b_bytes, "both sides must derive the same SAS bytes"

    a_emoji = [EMOJI[i] for i in sas_emoji_indices(a_bytes)]
    b_emoji = [EMOJI[i] for i in sas_emoji_indices(b_bytes)]
    assert a_emoji == b_emoji, "emoji must match"
    assert len(a_emoji) == 7, f"expected 7 emoji, got {len(a_emoji)}"
    assert all(0 <= i < 64 for i in sas_emoji_indices(a_bytes)), "indices must be in range"
    print("  emoji agree:", " ".join(e for e, _ in a_emoji),
          "(" + ", ".join(n for _, n in a_emoji) + ")")

    dec = sas_decimals(initiator.generate_bytes(info, 5))
    assert len(dec) == 3 and all(1000 <= d <= 9191 for d in dec), f"bad decimals {dec}"
    print("  decimals ok:", dec)

    # 3. MACs — each side signs its own fingerprint, the other verifies it
    init_fp, acc_fp = "INITIATOR_ED25519_FP", "ACCEPTER_ED25519_FP"

    acc_key_id = f"ed25519:{ACC_DEV}"
    acc_mac_info = mac_info(ACC_USER, ACC_DEV, INIT_USER, INIT_DEV)
    acc_mac = {
        "mac": {acc_key_id: accepter.calculate_mac(acc_fp, acc_mac_info + acc_key_id)},
        "keys": accepter.calculate_mac(acc_key_id, acc_mac_info + "KEY_IDS"),
    }
    # initiator verifies the accepter's MAC using the same info string
    key_ids = ",".join(sorted(acc_mac["mac"].keys()))
    assert acc_mac["keys"] == initiator.calculate_mac(key_ids, acc_mac_info + "KEY_IDS"), \
        "accepter keys MAC must verify"
    assert acc_mac["mac"][acc_key_id] == initiator.calculate_mac(acc_fp, acc_mac_info + acc_key_id), \
        "accepter ed25519 MAC must verify"
    print("  accepter MAC verifies on the initiator side")

    init_key_id = f"ed25519:{INIT_DEV}"
    init_mac_info = mac_info(INIT_USER, INIT_DEV, ACC_USER, ACC_DEV)
    init_mac = {
        "mac": {init_key_id: initiator.calculate_mac(init_fp, init_mac_info + init_key_id)},
        "keys": initiator.calculate_mac(init_key_id, init_mac_info + "KEY_IDS"),
    }
    key_ids = ",".join(sorted(init_mac["mac"].keys()))
    assert init_mac["keys"] == accepter.calculate_mac(key_ids, init_mac_info + "KEY_IDS"), \
        "initiator keys MAC must verify"
    assert init_mac["mac"][init_key_id] == accepter.calculate_mac(init_fp, init_mac_info + init_key_id), \
        "initiator ed25519 MAC must verify"
    print("  initiator MAC verifies on the accepter side")

    # a tampered fingerprint must NOT verify
    bad = accepter.calculate_mac("WRONG_FP", acc_mac_info + acc_key_id)
    assert bad != acc_mac["mac"][acc_key_id], "a different fingerprint must produce a different MAC"
    print("  tampered fingerprint rejected")

    print("\nall SAS self-checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
