"""超长事件链分段校验。

客户端把一条超长事件链拆成多段顺序提交：首段不带 ``continuation_token``，
后续段携带上一响应返回的 ``next_continuation_token``。令牌是不透明的，
完整保存继续推进状态机所需的全部封装状态：

* ``sealed`` / ``ever_sealed``：当前封装状态与“是否曾经封装”（reseal 语义）；
* ``custodian``：当前保管人；
* ``current_seal``：当前有效封签；
* ``used_seals``：全部已用封签（封签复用判定）；
* ``last_timestamp``：最近一个*有效*事件时间（严格递增判定）；
* ``event_count`` / ``violation_count``：累计事件数与累计违规数。

载荷经 base64url 编码后，用环境变量 ``SEAL_CHAIN_TOKEN_SECRET`` 指定的
密钥做确定性 HMAC-SHA256 签名（相同状态在同一密钥下产生完全相同的令牌）。
签名不符、版本不支持或任何状态字段非法（含字段缺失 / 多余 / 类型非法 /
状态不变量不成立）一律抛出 ``ChunkTokenError``（路由层转为 422），并且
**在令牌校验通过前绝不处理本段事件**。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime
from typing import Any, List, Optional, Set, Tuple

from .models import (
    ChunkSummary,
    Event,
    EventResult,
    ValidateChunkRequest,
    ValidateChunkResponse,
    Violation,
)
from .validator import ChainState, run_state_machine

#: 令牌载荷版本；不支持的版本（含被篡改）一律 422
_TOKEN_VERSION = 1

#: 签名密钥环境变量；未设置时使用仅适用于本地开发 / 测试的默认值。
#: 生产环境务必通过 SEAL_CHAIN_TOKEN_SECRET 注入稳定密钥：更换密钥后，
#: 旧令牌会因签名校验失败而无法续接（422）。
_TOKEN_SECRET_ENV = "SEAL_CHAIN_TOKEN_SECRET"
_DEFAULT_TOKEN_SECRET = "seal-chain-dev-token-secret-change-me"

#: 令牌载荷中允许出现的全部字段（白名单，多余字段即视为非法）
_PAYLOAD_FIELDS = frozenset(
    {
        "v",
        "sealed",
        "ever_sealed",
        "current_seal",
        "custodian",
        "used_seals",
        "last_timestamp",
        "event_count",
        "violation_count",
    }
)


class ChunkTokenError(ValueError):
    """续接令牌非法（篡改 / 版本不支持 / 状态字段非法），路由层转为 422。"""


def _token_secret() -> bytes:
    """读取用于令牌签名的密钥（同一进程内每次读取结果一致）。

    环境变量未设置或为空字符串时，回退到仅适用于本地开发 / 测试的默认值。
    """
    return (os.environ.get(_TOKEN_SECRET_ENV) or _DEFAULT_TOKEN_SECRET).encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    try:
        padding = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise ChunkTokenError("续接令牌编码非法") from exc


def _sign(payload_b64: str, secret: bytes) -> str:
    digest = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(digest)


def _encode_state(
    state: ChainState, event_count: int, violation_count: int
) -> str:
    """把封装状态与累计计数序列化为签名后的不透明令牌。"""
    payload: dict[str, Any] = {
        "v": _TOKEN_VERSION,
        "sealed": state.sealed,
        "ever_sealed": state.ever_sealed,
        "current_seal": state.current_seal,
        "custodian": state.custodian,
        # 排序保证确定性；经 set 去重
        "used_seals": sorted(state.used_seals),
        "last_timestamp": (
            state.last_timestamp.isoformat() if state.last_timestamp is not None else None
        ),
        "event_count": event_count,
        "violation_count": violation_count,
    }
    # 固定分隔符与排序键，保证签名确定
    payload_raw = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    payload_b64 = _b64url_encode(payload_raw)
    signature = _sign(payload_b64, _token_secret())
    return f"{payload_b64}.{signature}"


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ChunkTokenError(f"续接令牌状态字段非法：{name} 必须为布尔值")
    return value


def _require_nonneg_int(value: Any, name: str) -> int:
    # bool 是 int 的子类，须显式排除
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ChunkTokenError(f"续接令牌状态字段非法：{name} 必须为非负整数")
    return value


def _require_optional_str(value: Any, name: str) -> Optional[str]:
    if value is not None and not isinstance(value, str):
        raise ChunkTokenError(f"续接令牌状态字段非法：{name} 必须为字符串或 null")
    return value


def _parse_payload(payload_b64: str) -> dict[str, Any]:
    """解码令牌载荷，校验签名、版本与全部状态字段，失败一律 422。"""
    raw = _b64url_decode(payload_b64)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChunkTokenError("续接令牌载荷非法") from exc
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        raise ChunkTokenError("续接令牌状态字段非法：字段缺失或包含多余字段")

    if payload["v"] != _TOKEN_VERSION:
        raise ChunkTokenError(
            f"不支持的续接令牌版本：{payload['v']!r}（当前支持版本 {_TOKEN_VERSION}）"
        )

    sealed = _require_bool(payload["sealed"], "sealed")
    ever_sealed = _require_bool(payload["ever_sealed"], "ever_sealed")
    current_seal = _require_optional_str(payload["current_seal"], "current_seal")
    custodian = _require_optional_str(payload["custodian"], "custodian")
    used_seals_raw = payload["used_seals"]
    if not isinstance(used_seals_raw, list) or not all(
        isinstance(item, str) for item in used_seals_raw
    ):
        raise ChunkTokenError("续接令牌状态字段非法：used_seals 必须为字符串数组")
    last_timestamp_raw = _require_optional_str(
        payload["last_timestamp"], "last_timestamp"
    )
    event_count = _require_nonneg_int(payload["event_count"], "event_count")
    violation_count = _require_nonneg_int(
        payload["violation_count"], "violation_count"
    )

    last_timestamp: Optional[datetime] = None
    if last_timestamp_raw is not None:
        try:
            last_timestamp = datetime.fromisoformat(last_timestamp_raw)
        except ValueError as exc:
            raise ChunkTokenError(
                "续接令牌状态字段非法：last_timestamp 不是合法 ISO 8601 时间"
            ) from exc

    # 状态字段不变量（任何篡改导致的不一致都在此拦截）
    used_seals: Set[str] = set(used_seals_raw)
    if sealed and not ever_sealed:
        raise ChunkTokenError("续接令牌状态字段非法：sealed 为真时 ever_sealed 必须为真")
    if sealed and not current_seal:
        raise ChunkTokenError(
            "续接令牌状态字段非法：sealed 为真时 current_seal 必须存在"
        )
    if current_seal is not None and current_seal not in used_seals:
        raise ChunkTokenError(
            "续接令牌状态字段非法：current_seal 必须包含在 used_seals 中"
        )
    if not sealed and current_seal is not None:
        raise ChunkTokenError(
            "续接令牌状态字段非法：未封装时 current_seal 必须为 null"
        )
    if ever_sealed and not used_seals:
        raise ChunkTokenError(
            "续接令牌状态字段非法：ever_sealed 为真时 used_seals 不得为空"
        )
    if violation_count > event_count:
        raise ChunkTokenError(
            "续接令牌状态字段非法：violation_count 不得超过 event_count"
        )

    payload["sealed"] = sealed
    payload["ever_sealed"] = ever_sealed
    payload["current_seal"] = current_seal
    payload["custodian"] = custodian
    payload["used_seals"] = used_seals
    payload["last_timestamp"] = last_timestamp
    payload["event_count"] = event_count
    payload["violation_count"] = violation_count
    return payload


def decode_token(token: str) -> Tuple[ChainState, int, int]:
    """校验并解码续接令牌，返回 (封装状态, 累计事件数, 累计违规数)。

    任何篡改 / 版本不支持 / 状态字段非法都抛出 ``ChunkTokenError``。
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise ChunkTokenError("续接令牌格式非法")
    payload_b64, signature = token.split(".", 1)
    if not payload_b64 or not signature:
        raise ChunkTokenError("续接令牌格式非法")

    expected = _sign(payload_b64, _token_secret())
    if not hmac.compare_digest(signature, expected):
        raise ChunkTokenError("续接令牌签名校验失败（已篡改或密钥不一致）")

    payload = _parse_payload(payload_b64)
    state = ChainState(
        sealed=payload["sealed"],
        ever_sealed=payload["ever_sealed"],
        current_seal=payload["current_seal"],
        custodian=payload["custodian"],
        used_seals=payload["used_seals"],
        last_timestamp=payload["last_timestamp"],
    )
    return state, payload["event_count"], payload["violation_count"]


def validate_chunk(request: ValidateChunkRequest) -> ValidateChunkResponse:
    """分段校验：先完整校验续接令牌（首段除外），再从保存的状态推进本段。"""
    if request.continuation_token is None:
        state = ChainState()
        event_count = 0
        violation_count = 0
    else:
        # 令牌必须先通过全部校验，之后才会触碰本段事件
        state, event_count, violation_count = decode_token(
            request.continuation_token
        )

    results: List[EventResult]
    violations: List[Violation]
    results, violations = run_state_machine(
        state, request.events, index_offset=event_count
    )

    chunk_violations = len(violations)
    event_count += len(request.events)
    violation_count += chunk_violations

    summary = ChunkSummary(
        processed_events=event_count,
        violation_count=violation_count,
        valid=violation_count == 0,
        sealed=state.sealed,
        final_custodian=state.custodian,
        current_seal=state.current_seal,
    )
    next_token = _encode_state(state, event_count, violation_count)

    return ValidateChunkResponse(
        events=results,
        violations=violations,
        summary=summary,
        next_continuation_token=next_token,
    )
