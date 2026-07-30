from chutes_common.auth import (
    _consume_v2_nonce,
    sign_request,
)
from chutes_common.constants import (
    HOTKEY_HEADER,
    MINER_HEADER,
    VALIDATOR_HEADER,
)
from chutes_common.settings import miner_settings


def test_validator_request_uses_attested_session_without_wallet_signature():
    headers, payload = sign_request(purpose="miner")

    assert payload is None
    assert headers[HOTKEY_HEADER] == miner_settings.miner_ss58
    assert headers["X-Chutes-Attested-Session"] == miner_settings.attested_session
    assert len(headers) == 2


def test_management_request_uses_same_scoped_attested_session():
    target = "/miner/servers/?include=tee"
    headers, payload = sign_request(
        management=True,
        method="GET",
        path=target,
    )

    assert payload is None
    assert headers[MINER_HEADER] == miner_settings.miner_ss58
    assert headers[VALIDATOR_HEADER] == miner_settings.miner_ss58
    assert headers["X-Chutes-Attested-Session"] == miner_settings.attested_session
    assert len(headers) == 3


def test_v2_nonce_consumption_is_single_use(monkeypatch):
    consumed = set()

    class Redis:
        def set(self, key, _value, *, nx, ex):
            assert nx is True
            assert ex == 30
            if key in consumed:
                return False
            consumed.add(key)
            return True

    class RedisClient:
        redis = Redis()

    monkeypatch.setattr(
        "chutes_common.redis.MonitoringRedisClient",
        RedisClient,
    )

    assert _consume_v2_nonce("signer", "123.random", ttl_seconds=30)
    assert not _consume_v2_nonce("signer", "123.random", ttl_seconds=30)


def test_v2_nonce_consumption_fails_closed(monkeypatch):
    class UnavailableRedis:
        def __init__(self):
            raise RuntimeError("redis unavailable")

    monkeypatch.setattr(
        "chutes_common.redis.MonitoringRedisClient",
        UnavailableRedis,
    )

    assert not _consume_v2_nonce("signer", "123.random", ttl_seconds=30)
