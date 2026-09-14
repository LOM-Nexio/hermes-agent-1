"""SAS (emoji) interactive verification for the Hermes Matrix bot.

mautrix-python 0.21.1 ships no ``m.key.verification.*`` handling at all, so
Element's "Verify User" request is silently dropped and the dialog hangs on
"Waiting for … to accept". This module implements the accepter half of the
short-authentication-string flow so that verification actually completes.

We are always the ACCEPTER: Element initiates, we answer. Flow:

    them: m.key.verification.request   -> us: ready
    them: m.key.verification.start     -> us: accept   (with commitment)
    them: m.key.verification.key       -> us: key      (then we show emoji)
    user confirms in chat              -> us: mac
    them: m.key.verification.mac       -> us: done

Crypto is ported from matrix-nio 0.20.2 (nio/crypto/sas.py). The olm provider is
fresholm (vodozemac); ``import fresholm.import_hook`` maps ``import olm`` onto
``fresholm.compat.olm``, which exposes a python-olm compatible ``olm.Sas``.

Spec: https://spec.matrix.org/latest/client-server-api/#short-authentication-string-sas-verification
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# fresholm maps `import olm` to its python-olm compatible shim.
import fresholm.import_hook  # noqa: F401  (side-effecting import hook)
import olm  # type: ignore  # noqa: E402

__all__ = ["SasVerifier", "EMOJI", "sas_emoji_indices", "canonical_json"]

# Matrix SAS emoji table, verbatim from nio/crypto/sas.py (64 entries, index = 6 bits).
EMOJI: List[Tuple[str, str]] = [
    ("🐶", "Dog"), ("🐱", "Cat"), ("🦁", "Lion"), ("🐎", "Horse"),
    ("🦄", "Unicorn"), ("🐷", "Pig"), ("🐘", "Elephant"), ("🐰", "Rabbit"),
    ("🐼", "Panda"), ("🐓", "Rooster"), ("🐧", "Penguin"), ("🐢", "Turtle"),
    ("🐟", "Fish"), ("🐙", "Octopus"), ("🦋", "Butterfly"), ("🌷", "Flower"),
    ("🌳", "Tree"), ("🌵", "Cactus"), ("🍄", "Mushroom"), ("🌏", "Globe"),
    ("🌙", "Moon"), ("☁️", "Cloud"), ("🔥", "Fire"), ("🍌", "Banana"),
    ("🍎", "Apple"), ("🍓", "Strawberry"), ("🌽", "Corn"), ("🍕", "Pizza"),
    ("🎂", "Cake"), ("❤️", "Heart"), ("😀", "Smiley"), ("🤖", "Robot"),
    ("🎩", "Hat"), ("👓", "Glasses"), ("🔧", "Wrench"), ("🎅", "Santa"),
    ("👍", "Thumbs up"), ("☂️", "Umbrella"), ("⌛", "Hourglass"), ("⏰", "Clock"),
    ("🎁", "Gift"), ("💡", "Light Bulb"), ("📕", "Book"), ("✏️", "Pencil"),
    ("📎", "Paperclip"), ("✂️", "Scissors"), ("🔒", "Lock"), ("🔑", "Key"),
    ("🔨", "Hammer"), ("☎️", "Telephone"), ("🏁", "Flag"), ("🚂", "Train"),
    ("🚲", "Bicycle"), ("✈️", "Airplane"), ("🚀", "Rocket"), ("🏆", "Trophy"),
    ("⚽", "Ball"), ("🎸", "Guitar"), ("🎺", "Trumpet"), ("🔔", "Bell"),
    ("⚓", "Anchor"), ("🎧", "Headphones"), ("📁", "Folder"), ("📌", "Pin"),
]

SAS_METHOD = "m.sas.v1"
KEY_AGREEMENT = "curve25519-hkdf-sha256"
HASH_ALG = "sha256"
MAC_ALG = "hkdf-hmac-sha256"

TRANSACTION_TTL = 300.0      # 5 minutes, per the task spec
CONFIRM_TIMEOUT = 180.0      # ~3 minutes to answer in chat

_CONFIRM_WORDS = {"match", "matches", "yes", "verify yes", "y", "confirm", "ok", "okay", "same"}
_REJECT_WORDS = {"no", "nope", "different", "mismatch", "cancel", "abort"}

# to-device event types we care about, suffix -> full type
_VERIFICATION_EVENTS = ("request", "ready", "start", "accept", "key", "mac", "done", "cancel")


def canonical_json(content: dict) -> str:
    """Matrix canonical JSON. mautrix has no helper for this."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sas_emoji_indices(sas_bytes: bytes) -> List[int]:
    """First 42 bits of *sas_bytes* as 7 six-bit indices into EMOJI."""
    bits = "".join(f"{b:08b}" for b in sas_bytes)
    return [int(bits[i:i + 6], 2) for i in range(0, 42, 6)]


def sas_decimals(sas_bytes: bytes) -> Tuple[int, int, int]:
    """Three 4-digit numbers, per the spec (13 bits each, +1000)."""
    bits = "".join(f"{b:08b}" for b in sas_bytes)[:-1]
    return tuple(int(bits[i:i + 13], 2) + 1000 for i in range(0, 39, 13))  # type: ignore[return-value]


def _as_dict(content: Any) -> dict:
    """ToDeviceEvent.content may be a parsed object, not a dict. Normalise."""
    if isinstance(content, dict):
        return content
    for attr in ("serialize", "_asdict"):
        fn = getattr(content, attr, None)
        if callable(fn):
            try:
                out = fn()
                if isinstance(out, dict):
                    return out
            except Exception:
                pass
    try:
        return dict(vars(content))
    except Exception:
        return {}


@dataclass
class _Txn:
    """One in-flight verification, keyed by (user, device, transaction_id)."""
    user: str
    device: str
    tx_id: str
    created: float = field(default_factory=time.monotonic)
    sas: Any = None
    start_content: Optional[dict] = None
    their_key: Optional[str] = None
    emoji_shown_at: Optional[float] = None
    our_mac_sent: bool = False
    their_mac: Optional[dict] = None
    room_id: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.user, self.device, self.tx_id)

    def expired(self, now: float) -> bool:
        return (now - self.created) > TRANSACTION_TTL

    def awaiting_confirmation(self) -> bool:
        return self.emoji_shown_at is not None and not self.our_mac_sent

    def confirmation_timed_out(self, now: float) -> bool:
        return (self.emoji_shown_at is not None and not self.our_mac_sent
                and (now - self.emoji_shown_at) > CONFIRM_TIMEOUT)


class SasVerifier:
    """Accepter-side SAS verification driven by to-device events.

    The adapter supplies callables so this module stays free of adapter internals:
      * ``is_authorized(user_id) -> bool``
      * ``send_message(user_id, text) -> awaitable`` — deliver text to that person's DM
      * ``on_verified(user_id, device_id)`` — optional, for persistence
    """

    def __init__(self, client: Any, own_user: str, own_device: str,
                 is_authorized: Callable[[str], bool],
                 send_message: Callable[[str, str], Any],
                 on_verified: Optional[Callable[[str, str], Any]] = None) -> None:
        self._client = client
        self._own_user = own_user
        self._own_device = own_device
        self._is_authorized = is_authorized
        self._send_message = send_message
        self._on_verified = on_verified
        self._txns: Dict[Tuple[str, str, str], _Txn] = {}

    # -- registration -----------------------------------------------------

    def register(self, client: Any) -> None:
        """Attach handlers for every m.key.verification.* to-device event.

        Custom event types MUST be built with t_class=TO_DEVICE, otherwise
        send_to_device() raises "Event type must be a to-device event type".
        """
        from mautrix.types import EventType
        for suffix in _VERIFICATION_EVENTS:
            evt = EventType.find(f"m.key.verification.{suffix}",
                                 t_class=EventType.Class.TO_DEVICE)
            client.add_event_handler(evt, self._dispatch)
        logger.info("Matrix: verification handlers registered (%d event types, device=%s)",
                    len(_VERIFICATION_EVENTS), self._own_device)

    def _event_type(self, name: str):
        from mautrix.types import EventType
        return EventType.find(f"m.key.verification.{name}", t_class=EventType.Class.TO_DEVICE)

    async def _send(self, user: str, device: str, name: str, content: dict) -> None:
        from mautrix.types import DeviceID, UserID
        await self._client.send_to_device(
            self._event_type(name), {UserID(user): {DeviceID(device): content}})
        logger.info("Matrix: verification -> %s to %s/%s", name, user, device)

    # -- dispatch ---------------------------------------------------------

    async def _dispatch(self, event: Any) -> None:
        try:
            raw_type = str(getattr(event, "type", ""))
            name = raw_type.rsplit(".", 1)[-1]
            sender = str(getattr(event, "sender", "") or "")
            content = _as_dict(getattr(event, "content", None))
            if sender == self._own_user:
                return  # our own echo
            self._reap(time.monotonic())
            handler = getattr(self, f"_on_{name}", None)
            if handler is None:
                return
            await handler(sender, content)
        except Exception as exc:
            logger.exception("Matrix: verification handler error: %s", exc)

    def _reap(self, now: float) -> None:
        for key, txn in list(self._txns.items()):
            if txn.expired(now):
                logger.info("Matrix: verification transaction %s expired", txn.tx_id)
                self._txns.pop(key, None)

    # -- protocol steps ---------------------------------------------------

    async def _on_request(self, sender: str, content: dict) -> None:
        tx_id = content.get("transaction_id") or ""
        device = content.get("from_device") or ""
        methods = content.get("methods") or []
        logger.info("Matrix: verification request from %s/%s tx=%s methods=%s",
                    sender, device, tx_id, methods)
        if not self._is_authorized(sender):
            logger.warning("Matrix: verification refused — %s is not an allowed user", sender)
            return
        if SAS_METHOD not in methods:
            await self._send(sender, device, "cancel", {
                "transaction_id": tx_id, "code": "m.unknown_method",
                "reason": "only m.sas.v1 is supported"})
            return
        txn = _Txn(user=sender, device=device, tx_id=tx_id)
        self._txns[txn.key] = txn
        await self._send(sender, device, "ready", {
            "transaction_id": tx_id, "from_device": self._own_device,
            "methods": [SAS_METHOD]})

    async def _on_start(self, sender: str, content: dict) -> None:
        tx_id = content.get("transaction_id") or ""
        device = content.get("from_device") or ""
        txn = self._txns.get((sender, device, tx_id))
        if txn is None:
            # Element may start without a prior request (device verification).
            if not self._is_authorized(sender):
                return
            txn = _Txn(user=sender, device=device, tx_id=tx_id)
            self._txns[txn.key] = txn

        def bad(code: str, reason: str):
            logger.warning("Matrix: verification start rejected (%s): %s", code, reason)
            return self._send(sender, device, "cancel",
                              {"transaction_id": tx_id, "code": code, "reason": reason})

        if content.get("method") != SAS_METHOD:
            return await bad("m.unknown_method", "method must be m.sas.v1")
        if KEY_AGREEMENT not in (content.get("key_agreement_protocols") or []):
            return await bad("m.unknown_method", "curve25519-hkdf-sha256 required")
        if HASH_ALG not in (content.get("hashes") or []):
            return await bad("m.unknown_method", "sha256 required")
        if MAC_ALG not in (content.get("message_authentication_codes") or []):
            return await bad("m.unknown_method", "hkdf-hmac-sha256 required")
        if "emoji" not in (content.get("short_authentication_string") or []):
            return await bad("m.unknown_method", "emoji SAS required")

        txn.sas = olm.Sas()
        txn.start_content = content
        # Commitment binds our key to THEIR start event, hashed over canonical JSON.
        commitment = olm.sha256(txn.sas.pubkey + canonical_json(content))
        await self._send(sender, device, "accept", {
            "transaction_id": tx_id,
            "method": SAS_METHOD,
            "key_agreement_protocol": KEY_AGREEMENT,
            "hash": HASH_ALG,
            "message_authentication_code": MAC_ALG,
            "short_authentication_string": ["emoji"],
            "commitment": commitment,
        })

    async def _on_key(self, sender: str, content: dict) -> None:
        tx_id = content.get("transaction_id") or ""
        txn = self._find(sender, tx_id)
        if txn is None or txn.sas is None:
            return
        their_key = content.get("key") or ""
        txn.their_key = their_key
        txn.sas.set_their_pubkey(their_key)
        await self._send(txn.user, txn.device, "key",
                         {"transaction_id": tx_id, "key": txn.sas.pubkey})
        emoji = self.emoji_for(txn)
        txn.emoji_shown_at = time.monotonic()
        pretty = "  ".join(e for e, _ in emoji)
        names = ", ".join(n for _, n in emoji)
        logger.info("Matrix: verification emoji for %s tx=%s: %s", txn.user, tx_id, names)
        await self._send_message(txn.user, (
            f"Verification for this session — do these match what Element is showing?\n\n"
            f"{pretty}\n\n{names}\n\n"
            f"Reply **match** (or **yes**) to confirm, or **no** to cancel."))

    def _sas_info(self, txn: _Txn) -> str:
        """They started, so their identity comes first."""
        return ("MATRIX_KEY_VERIFICATION_SAS"
                f"|{txn.user}|{txn.device}|{txn.their_key}"
                f"|{self._own_user}|{self._own_device}|{txn.sas.pubkey}"
                f"|{txn.tx_id}")

    def emoji_for(self, txn: _Txn) -> List[Tuple[str, str]]:
        data = txn.sas.generate_bytes(self._sas_info(txn), 6)
        return [EMOJI[i] for i in sas_emoji_indices(data)]

    # -- user confirmation ------------------------------------------------

    def pending_for_user(self, user_id: str) -> Optional[_Txn]:
        now = time.monotonic()
        for txn in self._txns.values():
            if txn.user == user_id and txn.awaiting_confirmation() and not txn.expired(now):
                return txn
        return None

    async def handle_chat_reply(self, user_id: str, text: str) -> bool:
        """Consume a chat message as a verification answer. True if consumed."""
        txn = self.pending_for_user(user_id)
        if txn is None:
            return False
        word = (text or "").strip().lower().strip(".!")
        now = time.monotonic()
        if txn.confirmation_timed_out(now):
            await self._cancel(txn, "m.timeout", "no confirmation in time")
            return False
        if word in _REJECT_WORDS:
            await self._cancel(txn, "m.user", "user said the emoji did not match")
            await self._send_message(user_id, "Verification cancelled — the emoji did not match.")
            return True
        if word not in _CONFIRM_WORDS:
            return False
        await self._send_our_mac(txn)
        return True

    async def _send_our_mac(self, txn: _Txn) -> None:
        key_id = f"ed25519:{self._own_device}"
        info = ("MATRIX_KEY_VERIFICATION_MAC" + self._own_user + self._own_device
                + txn.user + txn.device + txn.tx_id)
        our_fp = self._own_ed25519()
        content = {
            "transaction_id": txn.tx_id,
            "mac": {key_id: txn.sas.calculate_mac(our_fp, info + key_id)},
            "keys": txn.sas.calculate_mac(key_id, info + "KEY_IDS"),
        }
        txn.our_mac_sent = True
        await self._send(txn.user, txn.device, "mac", content)
        if txn.their_mac is not None:
            await self._finish(txn)

    async def _on_mac(self, sender: str, content: dict) -> None:
        tx_id = content.get("transaction_id") or ""
        txn = self._find(sender, tx_id)
        if txn is None:
            return
        txn.their_mac = content
        if txn.our_mac_sent:
            await self._finish(txn)

    async def _finish(self, txn: _Txn) -> None:
        if not self._verify_their_mac(txn):
            await self._cancel(txn, "m.mismatched_keys", "their MAC did not verify")
            await self._send_message(txn.user, "Verification failed: the key signatures did not match.")
            return
        await self._send(txn.user, txn.device, "done", {"transaction_id": txn.tx_id})
        self._txns.pop(txn.key, None)
        logger.info("Matrix: verification DONE with %s/%s", txn.user, txn.device)
        if self._on_verified:
            try:
                res = self._on_verified(txn.user, txn.device)
                if hasattr(res, "__await__"):
                    await res
            except Exception as exc:
                logger.warning("Matrix: verification persistence hook failed: %s", exc)
        await self._send_message(
            txn.user, "Verified. This session is now trusted, and encrypted rooms will share keys with me.")

    def _verify_their_mac(self, txn: _Txn) -> bool:
        theirs = txn.their_mac or {}
        macs = theirs.get("mac") or {}
        if not macs:
            return False
        info = ("MATRIX_KEY_VERIFICATION_MAC" + txn.user + txn.device
                + self._own_user + self._own_device + txn.tx_id)
        key_ids = ",".join(sorted(macs.keys()))
        if theirs.get("keys") != txn.sas.calculate_mac(key_ids, info + "KEY_IDS"):
            logger.warning("Matrix: verification key-ids MAC mismatch")
            return False
        their_fp = self._their_ed25519(txn.user, txn.device)
        if not their_fp:
            logger.warning("Matrix: verification — no ed25519 key known for %s/%s", txn.user, txn.device)
            return False
        expected_id = f"ed25519:{txn.device}"
        got = macs.get(expected_id)
        if got is None:
            logger.warning("Matrix: verification — their MAC has no entry for %s", expected_id)
            return False
        if got != txn.sas.calculate_mac(their_fp, info + expected_id):
            logger.warning("Matrix: verification — ed25519 MAC mismatch for %s", expected_id)
            return False
        return True

    # -- terminal events --------------------------------------------------

    async def _on_cancel(self, sender: str, content: dict) -> None:
        tx_id = content.get("transaction_id") or ""
        txn = self._find(sender, tx_id)
        logger.info("Matrix: verification cancelled by %s (%s): %s",
                    sender, content.get("code"), content.get("reason"))
        if txn is not None:
            self._txns.pop(txn.key, None)

    async def _on_done(self, sender: str, content: dict) -> None:
        tx_id = content.get("transaction_id") or ""
        txn = self._find(sender, tx_id)
        if txn is not None:
            self._txns.pop(txn.key, None)
            logger.info("Matrix: verification done ack from %s", sender)

    async def _on_ready(self, sender: str, content: dict) -> None:
        return  # we are the accepter; their ready needs no action

    async def _on_accept(self, sender: str, content: dict) -> None:
        return  # only meaningful when we initiate

    async def _cancel(self, txn: _Txn, code: str, reason: str) -> None:
        try:
            await self._send(txn.user, txn.device, "cancel",
                             {"transaction_id": txn.tx_id, "code": code, "reason": reason})
        finally:
            self._txns.pop(txn.key, None)

    # -- key material -----------------------------------------------------

    def _find(self, sender: str, tx_id: str) -> Optional[_Txn]:
        for txn in self._txns.values():
            if txn.user == sender and txn.tx_id == tx_id:
                return txn
        return None

    def _own_ed25519(self) -> str:
        acct = getattr(getattr(self._client, "crypto", None), "account", None)
        return str(getattr(acct, "signing_key", "") or "")

    def _their_ed25519(self, user: str, device: str) -> str:
        """Their ed25519 fingerprint from the crypto store's device list."""
        crypto = getattr(self._client, "crypto", None)
        for getter in ("get_device", "get_or_fetch_device"):
            fn = getattr(crypto, getter, None)
            if callable(fn):
                try:
                    dev = fn(user, device)
                    if dev is not None and not hasattr(dev, "__await__"):
                        key = getattr(dev, "signing_key", None)
                        if key:
                            return str(key)
                except Exception:
                    pass
        store = getattr(crypto, "crypto_store", None) or getattr(crypto, "store", None)
        getter = getattr(store, "get_device", None)
        if callable(getter):
            try:
                dev = getter(user, device)
                key = getattr(dev, "signing_key", None)
                if key:
                    return str(key)
            except Exception:
                pass
        return ""
