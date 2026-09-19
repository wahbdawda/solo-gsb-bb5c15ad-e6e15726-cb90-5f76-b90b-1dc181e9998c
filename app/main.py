"""封签链校验 API 入口。"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .batch import validate_batch
from .exposure import ExposureAuditError, audit_exposure
from .models import (
    BatchValidateRequest,
    BatchValidateResponse,
    ExposureAuditRequest,
    ExposureAuditResponse,
    ReconcileRequest,
    ReconcileResponse,
    ValidateRequest,
    ValidateResponse,
)
from .reconcile import reconcile
from .validator import validate_events

app = FastAPI(
    title="封签链校验 API",
    description="用于展品运输交接场景的封签链状态机校验服务",
    version="1.3.0",
)


@app.get("/health", tags=["meta"])
def health() -> dict:
    """健康检查。"""
    return {"status": "ok"}


@app.post(
    "/api/v1/seal-chain/validate",
    response_model=ValidateResponse,
    tags=["seal-chain"],
    summary="校验封签链事件序列",
)
def validate(request: ValidateRequest) -> ValidateResponse:
    """按状态机逐事件校验，返回最终保管人、当前封签、逐事件状态与全部违规。"""
    return validate_events(request.events)


@app.post(
    "/api/v1/seal-chain/batch-validate",
    response_model=BatchValidateResponse,
    tags=["seal-chain"],
    summary="批量封签占用检查（跨链冲突）",
)
def batch_validate(request: BatchValidateRequest) -> BatchValidateResponse:
    """先分别校验每条链，再按输入顺序建立全批次封签占用表，标记跨链占用冲突。"""
    return validate_batch(request)


@app.post(
    "/api/v1/seal-chain/reconcile-validate",
    response_model=ReconcileResponse,
    tags=["seal-chain"],
    summary="合并同一链的多个离线片段，重建唯一序列并校验",
)
def reconcile_validate(request: ReconcileRequest) -> ReconcileResponse:
    """按 event_id 去重（内容分歧返回冲突明细），按 prev_event_id 重建唯一序列
    （报告多头 / 缺失前驱 / 分叉 / 环，不按时间戳猜序），仅重建成功时调用
    现有单链校验器，并返回每个事件的来源片段编号列表。"""
    return reconcile(request)


@app.post(
    "/api/v1/seal-chain/exposure-audit",
    response_model=ExposureAuditResponse,
    tags=["seal-chain"],
    summary="开封暴露审计：开封区间相对授权开窗窗口的区间差",
)
def exposure_audit(request: ExposureAuditRequest) -> ExposureAuditResponse:
    """保留原单链校验结果；仅以其中 status=ok 的 unseal/reseal 推导半开开封区间
    [start,end)（末次开封未重封延伸至 audit_until），先合并相交或首尾相接的
    授权窗口，再逐段做区间差，返回 covered / uncovered 分段、未授权总秒数及
    对应事件下标。audit_until 早于最后一个有效事件时间时返回 422。"""
    try:
        return audit_exposure(request)
    except ExposureAuditError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
