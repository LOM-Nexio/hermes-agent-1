"""Offline end-to-end flow check: drives SasVerifier with a simulated Element.

This exercises the real handler code (dispatch, content normalisation, commitment,
emoji, MAC verification), not just the crypto primitives. No homeserver needed.

Run:
  "%LOCALAPPDATA%\\hermes\\hermes-agent\\venv\\Scripts\\python.exe" verification_flowcheck.py
"""

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).parent))

import fresholm.import_hook  # noqa: F401
import olm  # type: ignore

from verification import EMOJI, SasVerifier, canonical_json, sas_emoji_indices

BOT_USER, BOT_DEV = "@hermes:matrix.nexio.ca", "CNIBLMHDAS"
USER, USER_DEV = "@gurpreet:matrix.nexio.ca", "ELEMENTDEV"
TX = "flowcheck-tx"
BOT_FP, USER_FP = "BOT_ED25519_FINGERPRINT", "USER_ED25519_FINGERPRINT"


class FakeClient:
    def __init__(self):
        self.sent = []  # (type_str, content)
        self.device_id = BOT_DEV
        self.crypto = SimpleNamespace(account=SimpleNamespace(signing_key=BOT_FP))

    def add_event_handler(self, evt, fn):
        pass

    async def send_to_device(self, evt, payload):
        for _u, devs in payload.items():
            for _d, content in devs.items():
                self.sent.append((str(evt), content))

    def last(self, suffix):
        for t, c in reversed(self.sent):
            if t.endswith(suffix):
                return c
        return None


def evt(name, content):
    return SimpleNamespace(type=f"m.key.verification.{name}", sender=USER, content=content)


async def main() -> int:
    client = FakeClient()
    chat = []

    async def send_message(user, text):
        chat.append((user, text))

    v = SasVerifier(client, BOT_USER, BOT_DEV, lambda u: u == USER, send_message)
    v._their_ed25519 = lambda u, d: USER_FP  # crypto store is not available offline

    element = olm.Sas()

    # 1. request -> ready
    await v._dispatch(evt("request", {
        "transaction_id": TX, "from_device": USER_DEV, "methods": ["m.sas.v1"]}))
    ready = client.last("ready")
    assert ready and ready["methods"] == ["m.sas.v1"], f"expected ready, got {client.sent}"
    assert ready["from_device"] == BOT_DEV
    print("  1. request -> ready")

    # 2. start -> accept (with commitment over the RAW start content)
    start = {
        "from_device": USER_DEV, "method": "m.sas.v1", "transaction_id": TX,
        "key_agreement_protocols": ["curve25519-hkdf-sha256"], "hashes": ["sha256"],
        "message_authentication_codes": ["hkdf-hmac-sha256"],
        "short_authentication_string": ["emoji", "decimal"],
    }
    await v._dispatch(evt("start", start))
    accept = client.last("accept")
    assert accept, "expected accept"
    assert accept["key_agreement_protocol"] == "curve25519-hkdf-sha256"
    assert accept["short_authentication_string"] == ["emoji"]
    print("  2. start -> accept")

    txn = v._find(USER, TX)
    assert accept["commitment"] == olm.sha256(txn.sas.pubkey + canonical_json(start)), \
        "commitment must hash our pubkey + canonical start content"
    print("  3. commitment verifies against the start event")

    # 3. key exchange
    element.set_their_pubkey(txn.sas.pubkey)
    await v._dispatch(evt("key", {"transaction_id": TX, "key": element.pubkey}))
    our_key = client.last("key")
    assert our_key and our_key["key"] == txn.sas.pubkey, "must send our pubkey"
    print("  4. key -> key")

    # emoji must match what Element derives
    info = ("MATRIX_KEY_VERIFICATION_SAS"
            f"|{USER}|{USER_DEV}|{element.pubkey}"
            f"|{BOT_USER}|{BOT_DEV}|{txn.sas.pubkey}|{TX}")
    theirs = [EMOJI[i] for i in sas_emoji_indices(element.generate_bytes(info, 6))]
    ours = v.emoji_for(txn)
    assert ours == theirs, f"emoji mismatch:\n ours={ours}\n theirs={theirs}"
    assert chat and "match" in chat[-1][1].lower(), "must ask the user to confirm in chat"
    assert all(e in chat[-1][1] for e, _ in ours), "all 7 emoji must appear in the chat message"
    print("  5. emoji agree with Element:", " ".join(e for e, _ in ours))

    # unrelated chat must NOT be swallowed while we wait
    assert await v.handle_chat_reply(USER, "what's the weather") is False, \
        "ordinary chat must pass through to the agent"
    print("  6. unrelated chat is not consumed")

    # 4. user confirms -> mac
    assert await v.handle_chat_reply(USER, "match") is True
    mac = client.last("mac")
    assert mac and "keys" in mac and mac["mac"], "expected our mac"
    mac_info = "MATRIX_KEY_VERIFICATION_MAC" + BOT_USER + BOT_DEV + USER + USER_DEV + TX
    kid = f"ed25519:{BOT_DEV}"
    assert mac["mac"][kid] == element.calculate_mac(BOT_FP, mac_info + kid), \
        "our ed25519 MAC must verify on Element's side"
    assert mac["keys"] == element.calculate_mac(kid, mac_info + "KEY_IDS")
    print("  7. confirm -> mac, verifies on Element's side")

    # 5. their mac -> done
    their_info = "MATRIX_KEY_VERIFICATION_MAC" + USER + USER_DEV + BOT_USER + BOT_DEV + TX
    their_kid = f"ed25519:{USER_DEV}"
    await v._dispatch(evt("mac", {
        "transaction_id": TX,
        "mac": {their_kid: element.calculate_mac(USER_FP, their_info + their_kid)},
        "keys": element.calculate_mac(their_kid, their_info + "KEY_IDS"),
    }))
    assert client.last("done") is not None, "expected done"
    assert v._find(USER, TX) is None, "transaction must be cleared on completion"
    print("  8. their mac -> done, transaction cleared")

    # a forged MAC must be refused
    c2 = FakeClient()
    v2 = SasVerifier(c2, BOT_USER, BOT_DEV, lambda u: u == USER, send_message)
    v2._their_ed25519 = lambda u, d: USER_FP
    e2 = olm.Sas()
    await v2._dispatch(evt("request", {"transaction_id": TX, "from_device": USER_DEV,
                                       "methods": ["m.sas.v1"]}))
    await v2._dispatch(evt("start", start))
    t2 = v2._find(USER, TX)
    e2.set_their_pubkey(t2.sas.pubkey)
    await v2._dispatch(evt("key", {"transaction_id": TX, "key": e2.pubkey}))
    await v2.handle_chat_reply(USER, "yes")
    await v2._dispatch(evt("mac", {
        "transaction_id": TX,
        "mac": {their_kid: e2.calculate_mac("ATTACKER_FP", their_info + their_kid)},
        "keys": e2.calculate_mac(their_kid, their_info + "KEY_IDS"),
    }))
    assert c2.last("done") is None, "a forged MAC must NOT produce done"
    assert c2.last("cancel") is not None, "a forged MAC must cancel"
    print("  9. forged MAC is rejected and cancelled")

    # a non-allowed sender is ignored
    c3 = FakeClient()
    v3 = SasVerifier(c3, BOT_USER, BOT_DEV, lambda u: False, send_message)
    await v3._dispatch(evt("request", {"transaction_id": TX, "from_device": USER_DEV,
                                       "methods": ["m.sas.v1"]}))
    assert not c3.sent, "an unauthorized sender must get no reply"
    print(" 10. unauthorized sender ignored")

    print("\nall verification flow checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
