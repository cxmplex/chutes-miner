from chutes_common.auth import (
    _consume_v2_nonce,
    build_v2_message_mgmt,
    get_signing_message,
    sign_request,
)
from chutes_common.constants import (
    HOTKEY_HEADER,
    MINER_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
    SIG_VERSION_HEADER,
    SIG_VERSION_V2,
    VALIDATOR_HEADER,
)
from chutes_common.settings import miner_settings


def test_v1_signature_contract_remains_available():
    headers, payload = sign_request(purpose="miner")
    nonce = headers[NONCE_HEADER]
    message = get_signing_message(
        miner_settings.miner_ss58,
        nonce,
        payload_str=None,
        purpose="miner",
    )

    assert payload is None
    assert nonce.isdigit()
    assert SIG_VERSION_HEADER not in headers
    assert headers[HOTKEY_HEADER] == miner_settings.miner_ss58
    assert miner_settings.miner_keypair.verify(
        message,
        bytes.fromhex(headers[SIGNATURE_HEADER]),
    )


def test_v2_management_signature_binds_method_target_and_unique_nonce():
    target = "/miner/servers/?include=tee"
    headers, payload = sign_request(
        management=True,
        method="GET",
        path=target,
    )
    second_headers, _ = sign_request(
        management=True,
        method="GET",
        path=target,
    )
    nonce = headers[NONCE_HEADER]
    message = build_v2_message_mgmt(
        miner_settings.miner_ss58,
        miner_settings.miner_ss58,
        "GET",
        target,
        nonce,
        None,
    )

    assert payload is None
    assert "." in nonce
    assert nonce != second_headers[NONCE_HEADER]
    assert headers[SIG_VERSION_HEADER] == SIG_VERSION_V2
    assert headers[MINER_HEADER] == miner_settings.miner_ss58
    assert headers[VALIDATOR_HEADER] == miner_settings.miner_ss58
    assert miner_settings.miner_keypair.verify(
        message,
        bytes.fromhex(headers[SIGNATURE_HEADER]),
    )


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

    assert _consume_v2_nonce("signer", "123.random")
    assert not _consume_v2_nonce("signer", "123.random")


def test_v2_nonce_consumption_fails_closed(monkeypatch):
    class UnavailableRedis:
        def __init__(self):
            raise RuntimeError("redis unavailable")

    monkeypatch.setattr(
        "chutes_common.redis.MonitoringRedisClient",
        UnavailableRedis,
    )

    assert not _consume_v2_nonce("signer", "123.random")
