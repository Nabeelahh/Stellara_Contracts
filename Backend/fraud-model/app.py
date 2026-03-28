from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import hashlib
import os
from typing import Tuple

try:
    import onnxruntime as ort
    _HAS_ORT = True
except Exception:
    _HAS_ORT = False

_ORT_SESSION = None


def load_onnx_model(path: str):
    global _ORT_SESSION
    if not _HAS_ORT:
        return False
    if not os.path.exists(path):
        return False
    try:
        _ORT_SESSION = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        return True
    except Exception:
        _ORT_SESSION = None
        return False

app = FastAPI(title="Fraud Model Scorer", version="0.1")


class ScorePaymentDto(BaseModel):
    tenantId: str
    email: str
    paymentMethodId: Optional[str] = None
    planId: Optional[str] = None
    isNewTenant: Optional[bool] = False
    ip: Optional[str] = None
    userAgent: Optional[str] = None
    amount: Optional[float] = None


class ScoreResult(BaseModel):
    score: float
    action: str
    reasons: List[str]


def heuristic_score(input: ScorePaymentDto) -> (float, List[str]):
    reasons = []
    score = 0.0
    disposable = {"mailinator.com", "dispostable.com", "10minutemail.com", "tempmail.com"}
    try:
        domain = (input.email or "").split("@")[-1].lower()
        if domain in disposable:
            score += 0.6
            reasons.append("disposable_email_domain")
    except Exception:
        pass

    if input.isNewTenant:
        score += 0.08
        reasons.append("new_tenant")

    if not input.paymentMethodId:
        score += 0.05
        reasons.append("no_payment_method")

    return min(1.0, max(0.0, score)), reasons


def gnn_score(input: ScorePaymentDto) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    # If ONNX runtime model is available, run inference
    try:
        if _ORT_SESSION is not None:
            # Simple feature vector: hash(email+tenant) -> float features placeholder
            key = (input.tenantId or "") + "|" + (input.email or "")
            hh = hashlib.sha256(key.encode("utf-8")).hexdigest()
            # deterministic pseudo-feature from hash split into 4 floats
            feats = [int(hh[i:i+8], 16) / 0xFFFFFFFF for i in range(0, 32, 8)]
            # build input dict for ONNX model; expects input name 'input'
            name = _ORT_SESSION.get_inputs()[0].name
            import numpy as _np
            arr = _np.array([feats], dtype=_np.float32)
            pred = _ORT_SESSION.run(None, {name: arr})
            # assume model outputs single float in pred[0]
            v = float(pred[0].flatten()[0])
            if v > 0.85:
                reasons.append("graph_anomaly")
            return float(v), reasons
    except Exception:
        # fallback to deterministic hash-based signal below
        pass

    # Fallback deterministic GNN-like signal: hash tenantId -> [0,1)
    h = hashlib.sha256((input.tenantId or "").encode("utf-8")).hexdigest()
    v = int(h[:8], 16) / 0xFFFFFFFF
    if v > 0.85:
        reasons.append("graph_anomaly")
    return v, reasons


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/score", response_model=ScoreResult)
def score(input: ScorePaymentDto):
    h_score, h_reasons = heuristic_score(input)
    g_score, g_reasons = gnn_score(input)

    # Simple ensemble: weighted average (heuristic 60%, gnn 40%)
    final_score = h_score * 0.6 + g_score * 0.4
    reasons = h_reasons + g_reasons + ["ensemble_v1"]

    if final_score >= 0.7:
        action = "block"
    elif final_score >= 0.35:
        action = "challenge"
    else:
        action = "allow"

    return ScoreResult(score=round(final_score, 3), action=action, reasons=reasons)


@app.on_event("startup")
def startup_event():
    # Attempt to load an ONNX model if present at ./models/gnn.onnx
    model_path = os.environ.get("GNN_MODEL_PATH", "./models/gnn.onnx")
    if _HAS_ORT and load_onnx_model(model_path):
        print(f"Loaded ONNX model from {model_path}")
    else:
        if not _HAS_ORT:
            print("onnxruntime not available; running fallback GNN")
        else:
            print(f"No ONNX model found at {model_path}; using fallback GNN")
