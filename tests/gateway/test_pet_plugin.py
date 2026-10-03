"""Nexio Pet platform plugin: frame -> MessageEvent, outbound frames carry user_id, config gates."""
import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import MessageType
from plugins.platforms.pet import adapter as pet

JPEG = "data:image/jpeg;base64," + base64.b64encode(b"\xff\xd8\xff\xe0fake").decode()


def _adapter(monkeypatch, url="http://127.0.0.1:8000"):
    monkeypatch.setenv("PET_RELAY_SECRET", "s3cret")
    with patch.object(pet, "_get_scoped_secret", lambda name, default=None: "s3cret"):
        return pet.PetAdapter(PlatformConfig(enabled=True, extra={"relay_url": url}))


class TestConfig:
    def test_validate_config_needs_a_relay_url(self, monkeypatch):
        monkeypatch.delenv("PET_RELAY_URL", raising=False)
        assert pet.validate_config(PlatformConfig(enabled=True)) is False
        assert pet.validate_config(PlatformConfig(enabled=True, extra={"relay_url": "http://x"})) is True
        monkeypatch.setenv("PET_RELAY_URL", "https://mcp.nexio.ca/")
        assert pet.validate_config(PlatformConfig(enabled=True)) is True
        assert pet._env_enablement()["relay_url"] == "https://mcp.nexio.ca"

    def test_urls_and_chat_ids(self):
        assert pet._ws_url("https://mcp.nexio.ca") == "wss://mcp.nexio.ca/pet/relay"
        assert pet._ws_url("http://127.0.0.1:8000") == "ws://127.0.0.1:8000/pet/relay"
        assert pet._http_url("ws://127.0.0.1:8000") == "http://127.0.0.1:8000"
        assert pet.chat_id_for("u-ada") == "dm:u-ada"
        assert pet.user_id_for("dm:u-ada") == "u-ada"
        assert pet.user_id_for("u-ada") == "u-ada"


class TestInbound:
    def test_text_frame_becomes_a_dm_event(self, monkeypatch):
        a = _adapter(monkeypatch)
        ev = a.build_event({"type": "message", "id": "m1", "text": "  hi there ", "user_id": "u-ada", "user_name": "Ada", "email": "ada@lom.ca"})
        assert ev.text == "hi there"
        assert ev.message_type is MessageType.TEXT
        assert (ev.user_id, ev.user_name, ev.message_id) == ("u-ada", "Ada", "m1")
        assert ev.source.chat_id == "dm:u-ada"
        assert ev.source.chat_type == "dm"
        assert ev.media_urls == []

    def test_screenshot_is_cached_and_marks_photo(self, monkeypatch):
        a = _adapter(monkeypatch)
        seen = {}

        def fake_cache(data, *, filename="", mime_type="", default_kind=None):
            seen.update(data=data, filename=filename, mime_type=mime_type, default_kind=default_kind)
            return SimpleNamespace(path="/tmp/screen.jpg", media_type="image/jpeg", kind="image")

        with patch.object(pet, "cache_media_bytes", fake_cache):
            ev = a.build_event({"type": "message", "id": "m2", "text": "", "image": JPEG, "user_id": "u-ada", "user_name": "Ada"})
        assert seen["data"] == b"\xff\xd8\xff\xe0fake"
        assert (seen["filename"], seen["mime_type"], seen["default_kind"]) == ("screen.jpg", "image/jpeg", "image")
        assert ev.media_urls == ["/tmp/screen.jpg"]
        assert ev.media_types == ["image/jpeg"]
        assert ev.message_type is MessageType.PHOTO
        assert ev.text == pet._NO_TEXT

    def test_empty_or_anonymous_frames_are_dropped(self, monkeypatch):
        a = _adapter(monkeypatch)
        assert a.build_event({"type": "message", "text": "hi"}) is None
        assert a.build_event({"type": "message", "text": "   ", "user_id": "u-ada"}) is None

    @pytest.mark.asyncio
    async def test_dispatch_hands_the_event_to_the_gateway(self, monkeypatch):
        a = _adapter(monkeypatch)
        a.handle_message = AsyncMock()
        await a._dispatch({"type": "message", "id": "m3", "text": "ping", "user_id": "u-bob", "user_name": "Bob"})
        ev = a.handle_message.await_args.args[0]
        assert ev.source.chat_id == "dm:u-bob"


class TestOutbound:
    @pytest.mark.asyncio
    async def test_frames_carry_user_id_and_stream(self, monkeypatch):
        a = _adapter(monkeypatch)
        ws = SimpleNamespace(closed=False, send_json=AsyncMock())
        a._ws = ws
        assert a.supports_draft_streaming(chat_id="dm:u-ada") is True
        r = await a.send_draft("dm:u-ada", 7, "Chec")
        assert r.success
        await a.send_typing("dm:u-ada")
        r = await a.send("dm:u-ada", "x" * 7000, reply_to="m1")
        assert r.success and r.message_id
        frames = [c.args[0] for c in ws.send_json.await_args_list]
        assert frames[0] == {"type": "draft", "user_id": "u-ada", "draft_id": 7, "text": "Chec"}
        assert frames[1] == {"type": "typing", "user_id": "u-ada"}
        assert (frames[2]["type"], frames[2]["user_id"], len(frames[2]["text"]), frames[2]["reply_to"]) == ("message", "u-ada", 6000, "m1")

    @pytest.mark.asyncio
    async def test_send_without_socket_is_retryable_failure(self, monkeypatch):
        a = _adapter(monkeypatch)
        r = await a.send("dm:u-ada", "hello")
        assert (r.success, r.retryable) == (False, True)

    @pytest.mark.asyncio
    async def test_standalone_send_posts_to_deliver(self, monkeypatch):
        monkeypatch.setenv("PET_RELAY_SECRET", "s3cret")
        calls = {}

        class _Resp:
            status = 200
            async def json(self):
                return {"delivered": False, "queued": True}
            async def text(self):
                return ""
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                return False

        class _Session:
            def post(self, url, **kw):
                calls.update(url=url, **kw)
                return _Resp()
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                return False

        with patch.object(pet, "_get_scoped_secret", lambda n, d=None: "s3cret"), \
             patch.object(pet.aiohttp, "ClientSession", lambda: _Session()):
            out = await pet._standalone_send(PlatformConfig(enabled=True, extra={"relay_url": "http://127.0.0.1:8000"}), "dm:u-ada", "Reminder: call Travis")
        assert out == {"success": True, "platform": "pet", "chat_id": "dm:u-ada", "queued": True}
        assert calls["url"] == "http://127.0.0.1:8000/pet/deliver"
        assert calls["json"] == {"user_id": "u-ada", "text": "Reminder: call Travis"}
        assert calls["headers"]["Authorization"] == "Bearer s3cret"
