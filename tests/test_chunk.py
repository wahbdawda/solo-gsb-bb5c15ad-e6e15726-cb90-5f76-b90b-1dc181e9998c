"""超长事件链分段校验的单元测试与 API 集成测试。"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app import chunk as chunk_mod
from app.chunk import ChunkTokenError, validate_chunk
from app.main import app
from app.models import Event, EventType, ValidateChunkRequest
from app.validator import validate_events

client = TestClient(app)

T = "2026-09-18T%02d:00:00Z"
PATH = "/api/v1/seal-chain/validate-chunk"


def ev(i: int, type_: EventType, **kw) -> Event:
    return Event(type=type_, timestamp=T % i, **kw)


def full_chain() -> list[Event]:
    return [
        ev(1, EventType.SEAL, seal_id="S001", custodian="Alice"),
        ev(2, EventType.HANDOVER, custodian="Bob"),
        ev(3, EventType.UNSEAL),
        ev(4, EventType.RESEAL, seal_id="S002", custodian="Bob"),
        ev(5, EventType.HANDOVER, custodian="Carol"),
    ]


def run_chunks(chunks: list[list[Event]]) -> tuple:
    """顺序提交多个分段，返回 (各段响应, 最后一段响应)。"""
    token = None
    responses = []
    for part in chunks:
        resp = validate_chunk(
            ValidateChunkRequest(events=part, continuation_token=token)
        )
        responses.append(resp)
        token = resp.next_continuation_token
    return responses, responses[-1]


# ---------------------------------------------------------------------------
# 与单链接口等价
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "split",
    [
        [5],          # 单段
        [1, 1, 1, 1, 1],
        [2, 3],
        [3, 2],
        [1, 4],
        [4, 1],
        [0, 2, 0, 3, 0],  # 含空段
    ],
)
def test_chunked_matches_single_chain(split):
    events = full_chain()
    chunks = []
    cursor = 0
    for size in split:
        chunks.append(events[cursor:cursor + size])
        cursor += size

    responses, last = run_chunks(chunks)
    single = validate_events(events)

    # 逐事件判定拼接后与单链接口完全一致（下标使用全链偏移）
    stitched_events = [item for resp in responses for item in resp.events]
    assert [e.model_dump() for e in stitched_events] == [
        e.model_dump() for e in single.events
    ]
    stitched_violations = [v for resp in responses for v in resp.violations]
    assert [v.model_dump() for v in stitched_violations] == [
        v.model_dump() for v in single.violations
    ]

    # 末段累计摘要与单链终态一致
    assert last.summary.processed_events == 5
    assert last.summary.violation_count == 0
    assert last.summary.valid is True
    assert last.summary.sealed is single.sealed
    assert last.summary.final_custodian == single.final_custodian
    assert last.summary.current_seal == single.current_seal


def test_chunked_indices_are_full_chain_offsets():
    events = [
        ev(1, EventType.SEAL, seal_id="S001", custodian="Alice"),
        ev(2, EventType.SEAL, seal_id="S002", custodian="Alice"),  # 重复封装
        ev(3, EventType.UNSEAL),
        ev(4, EventType.RESEAL, seal_id="S001", custodian="Alice"),  # 封签复用
    ]
    responses, last = run_chunks([events[:2], events[2:]])

    assert [e.index for e in responses[0].events] == [0, 1]
    assert [e.index for e in responses[1].events] == [2, 3]
    assert [v.index for v in responses[0].violations] == [1]
    assert [v.index for v in responses[1].violations] == [3]
    assert responses[1].violations[0].reason == "封签 S001 已被使用，不得复用"

    # 累计摘要
    assert last.summary.processed_events == 4
    assert last.summary.violation_count == 2
    assert last.summary.valid is False
    assert last.summary.sealed is False
    assert last.summary.current_seal is None


def test_violation_does_not_change_state_across_chunks():
    # 首段在已封装状态下出现一次违规开封尝试（不改变状态）
    first = [
        ev(1, EventType.SEAL, seal_id="S001", custodian="Alice"),
        ev(2, EventType.SEAL, seal_id="S002", custodian="Alice"),  # 违规
    ]
    r1 = validate_chunk(ValidateChunkRequest(events=first))
    assert [e.status for e in r1.events] == ["ok", "violation"]
    assert r1.summary.sealed is True
    assert r1.summary.current_seal == "S001"

    # 续段：状态仍是 S001 封装中
    second = [
        ev(3, EventType.HANDOVER, custodian="Bob"),
        ev(4, EventType.UNSEAL),
        ev(5, EventType.RESEAL, seal_id="S003", custodian="Bob"),
    ]
    r2 = validate_chunk(
        ValidateChunkRequest(events=second, continuation_token=r1.next_continuation_token)
    )
    assert [e.status for e in r2.events] == ["ok", "ok", "ok"]
    assert [e.index for e in r2.events] == [2, 3, 4]
    assert r2.summary.processed_events == 5
    assert r2.summary.violation_count == 1
    assert r2.summary.valid is False
    assert r2.summary.current_seal == "S003"


def test_timestamp_monotonicity_compared_across_chunks():
    # 第二段首事件时间不晚于第一段的最后一个有效事件 -> 违规
    first = [ev(10, EventType.SEAL, seal_id="S001", custodian="Alice")]
    r1 = validate_chunk(ValidateChunkRequest(events=first))
    second = [ev(10, EventType.HANDOVER, custodian="Bob")]  # 相等，违规
    r2 = validate_chunk(
        ValidateChunkRequest(events=second, continuation_token=r1.next_continuation_token)
    )
    assert r2.events[0].status == "violation"
    assert "严格递增" in r2.violations[0].reason


def test_used_seal_from_previous_chunk_cannot_be_reused():
    first = [
        ev(1, EventType.SEAL, seal_id="S001", custodian="Alice"),
        ev(2, EventType.UNSEAL),
    ]
    r1 = validate_chunk(ValidateChunkRequest(events=first))
    second = [ev(3, EventType.RESEAL, seal_id="S001", custodian="Alice")]
    r2 = validate_chunk(
        ValidateChunkRequest(events=second, continuation_token=r1.next_continuation_token)
    )
    assert r2.events[0].status == "violation"
    assert "不得复用" in r2.violations[0].reason


def test_empty_first_chunk_returns_usable_token():
    r1 = validate_chunk(ValidateChunkRequest(events=[]))
    assert r1.events == []
    assert r1.violations == []
    assert r1.summary.processed_events == 0
    assert r1.summary.valid is True
    # 空段令牌可续接，首事件仍是全链下标 0
    r2 = validate_chunk(
        ValidateChunkRequest(
            events=[ev(1, EventType.SEAL, seal_id="S001", custodian="Alice")],
            continuation_token=r1.next_continuation_token,
        )
    )
    assert r2.events[0].index == 0
    assert r2.summary.processed_events == 1


def test_aware_and_naive_timestamps_survive_token_roundtrip():
    aware = Event(
        type=EventType.SEAL,
        timestamp="2026-09-18T10:00:00+08:00",
        seal_id="S001",
        custodian="Alice",
    )
    r1 = validate_chunk(ValidateChunkRequest(events=[aware]))
    # 同带时区的续段事件可正常比较
    ok = Event(
        type=EventType.HANDOVER,
        timestamp="2026-09-18T11:00:00+08:00",
        custodian="Bob",
    )
    r2 = validate_chunk(
        ValidateChunkRequest(events=[ok], continuation_token=r1.next_continuation_token)
    )
    assert r2.events[0].status == "ok"

    # 混用不带时区时间 -> 与单链接口一致的违规原因
    naive = Event(
        type=EventType.HANDOVER,
        timestamp="2026-09-18T12:00:00",
        custodian="Carol",
    )
    r3 = validate_chunk(
        ValidateChunkRequest(
            events=[naive], continuation_token=r2.next_continuation_token
        )
    )
    assert r3.events[0].status == "violation"
    assert "时区信息不一致" in r3.violations[0].reason


# ---------------------------------------------------------------------------
# 令牌：确定性、篡改、版本、非法状态
# ---------------------------------------------------------------------------


def test_token_is_deterministic():
    events = [ev(1, EventType.SEAL, seal_id="S001", custodian="Alice")]
    r_a = validate_chunk(ValidateChunkRequest(events=events))
    r_b = validate_chunk(ValidateChunkRequest(events=events))
    assert r_a.next_continuation_token == r_b.next_continuation_token


def test_token_is_opaque_signed_two_part_string():
    r = validate_chunk(ValidateChunkRequest(events=[]))
    token = r.next_continuation_token
    assert token.count(".") == 1
    # 载荷仅为 base64url，不依赖其保密性，但签名段必须存在
    payload_b64, signature = token.split(".")
    raw = base64.urlsafe_b64decode(payload_b64 + "==")
    assert raw.startswith(b"{")
    assert len(signature) > 16


def test_token_signed_with_env_secret_rejected_after_secret_changes(monkeypatch):
    monkeypatch.setenv("SEAL_CHAIN_TOKEN_SECRET", "secret-A")
    r1 = validate_chunk(ValidateChunkRequest(events=full_chain()[:2]))
    token = r1.next_continuation_token

    # 换密钥后旧令牌签名失效
    monkeypatch.setenv("SEAL_CHAIN_TOKEN_SECRET", "secret-B")
    with pytest.raises(ChunkTokenError, match="签名"):
        validate_chunk(
            ValidateChunkRequest(events=full_chain()[2:3], continuation_token=token)
        )

    # 同一密钥下可正常续接
    monkeypatch.setenv("SEAL_CHAIN_TOKEN_SECRET", "secret-A")
    r2 = validate_chunk(
        ValidateChunkRequest(events=full_chain()[2:3], continuation_token=token)
    )
    assert r2.events[0].index == 2


def _tampered_payload_token(token: str, payload_obj: dict) -> str:
    """以当前密钥对被篡改的载荷重新分段（但不重签），制造签名不符。"""
    import json

    payload_b64, signature = token.split(".")
    raw = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode()
    new_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"{new_b64}.{signature}"


def test_tampered_signature_returns_422_and_events_not_processed(monkeypatch):
    calls = []
    original = chunk_mod.run_state_machine

    def spy(state, events, index_offset=0):  # 若在非法令牌请求中被调用即说明校验未拦住
        calls.append(len(events))
        return original(state, events, index_offset)

    monkeypatch.setattr(chunk_mod, "run_state_machine", spy)

    # 先用被 patch 的 spy 生成合法令牌（记录首段调用）
    r1 = client.post(
        PATH,
        json={"events": [
            {"type": "seal", "timestamp": T % 1, "seal_id": "S001", "custodian": "Alice"}
        ]},
    )
    assert r1.status_code == 200
    calls.clear()

    payload_b64, signature = r1.json()["next_continuation_token"].split(".")
    flipped = ("a" if payload_b64[0] != "a" else "b") + payload_b64[1:]

    resp = client.post(
        PATH,
        json={"events": [{"type": "handover", "timestamp": T % 2, "custodian": "Bob"}],
              "continuation_token": f"{flipped}.{signature}"},
    )
    assert resp.status_code == 422
    assert calls == []  # 令牌未通过校验，本段事件未被处理


def test_tampered_state_field_with_valid_signature_returns_422():
    r1 = validate_chunk(
        ValidateChunkRequest(events=[ev(1, EventType.SEAL, seal_id="S001", custodian="Alice")])
    )
    payload_b64, _ = r1.next_continuation_token.split(".")
    import json

    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))

    # 即使持有合法签名密钥，篡改载荷后重新签名也必须被字段不变量拒绝
    payload["sealed"] = False  # 与 current_seal/used_seals 矛盾
    token = _reencode_signed(payload)
    resp = client.post(
        PATH,
        json={"events": [], "continuation_token": token},
    )
    assert resp.status_code == 422


def _reencode_signed(payload_obj: dict) -> str:
    import json

    from app.chunk import _token_secret

    raw = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode()
    payload_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    import hashlib
    import hmac

    sig = hmac.new(_token_secret(), payload_b64.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{payload_b64}.{sig_b64}"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update({"v": 999}),                    # 版本不支持
        lambda p: p.update({"sealed": "yes"}),             # 类型非法
        lambda p: p.update({"event_count": -1}),           # 负数
        lambda p: p.update({"event_count": "3"}),          # 字符串数字
        lambda p: p.update({"violation_count": True}),     # bool 冒充 int
        lambda p: p.update({"used_seals": ["S001", 7]}),   # 数组元素非字符串
        lambda p: p.update({"used_seals": "S001"}),        # 非数组
        lambda p: p.update({"last_timestamp": "not-a-time"}),
        lambda p: p.update({"custodian": 123}),
        lambda p: p.update({"current_seal": "S999"}),      # 不在 used_seals
        lambda p: p.update({"sealed": False, "ever_sealed": False}),
        lambda p: p.update({"violation_count": 99}),       # 超过 event_count
        lambda p: p.pop("ever_sealed"),                    # 缺字段
        lambda p: p.update({"extra": 1}),                  # 多字段
    ],
)
def test_invalid_token_payloads_rejected(mutate):
    import json

    r1 = validate_chunk(
        ValidateChunkRequest(events=[ev(1, EventType.SEAL, seal_id="S001", custodian="Alice")])
    )
    payload_b64, _ = r1.next_continuation_token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    mutate(payload)

    with pytest.raises(ChunkTokenError):
        chunk_mod.decode_token(_reencode_signed(payload))


@pytest.mark.parametrize(
    "bad_token",
    [
        "",
        "garbage",
        "a.b.c",
        ".",
        "abc.",
        ".abc",
        "!!!.@@@",
    ],
)
def test_malformed_tokens_rejected(bad_token):
    with pytest.raises(ChunkTokenError):
        chunk_mod.decode_token(bad_token)


def test_invalid_token_does_not_process_events_via_api():
    resp = client.post(
        PATH,
        json={"events": [{"type": "seal", "timestamp": T % 1,
                          "seal_id": "S001", "custodian": "Alice"}],
              "continuation_token": "forged.xxxxx"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# API 集成
# ---------------------------------------------------------------------------


def test_api_full_flow_matches_single_chain():
    events = full_chain()
    r1 = client.post(PATH, json={"events": [e.model_dump(mode="json") for e in events[:3]]})
    assert r1.status_code == 200
    b1 = r1.json()
    assert [e["index"] for e in b1["events"]] == [0, 1, 2]
    assert b1["summary"] == {
        "processed_events": 3,
        "violation_count": 0,
        "valid": True,
        "sealed": False,
        "final_custodian": "Bob",
        "current_seal": None,
    }

    r2 = client.post(PATH, json={
        "events": [e.model_dump(mode="json") for e in events[3:]],
        "continuation_token": b1["next_continuation_token"],
    })
    assert r2.status_code == 200
    b2 = r2.json()
    assert [e["index"] for e in b2["events"]] == [3, 4]
    assert b2["summary"]["processed_events"] == 5
    assert b2["summary"]["valid"] is True
    assert b2["summary"]["current_seal"] == "S002"
    assert b2["summary"]["final_custodian"] == "Carol"


def test_api_first_chunk_with_null_token_ok():
    r = client.post(PATH, json={"events": [], "continuation_token": None})
    assert r.status_code == 200
    assert r.json()["summary"]["processed_events"] == 0


def test_api_malformed_event_structure_is_422():
    r = client.post(PATH, json={"events": [{"type": "teleport", "timestamp": T % 1}]})
    assert r.status_code == 422


def test_api_token_chained_across_three_requests():
    token = None
    seen_indices = []
    for part in [full_chain()[:2], full_chain()[2:4], full_chain()[4:]]:
        body = {"events": [e.model_dump(mode="json") for e in part]}
        if token is not None:
            body["continuation_token"] = token
        r = client.post(PATH, json=body)
        assert r.status_code == 200
        data = r.json()
        seen_indices.extend(e["index"] for e in data["events"])
        token = data["next_continuation_token"]
    assert seen_indices == [0, 1, 2, 3, 4]
