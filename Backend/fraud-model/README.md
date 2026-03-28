Fraud Model Service
===================

This is a minimal FastAPI-based scorer that demonstrates an ensemble of a heuristic and
a graph-derived signal (placeholder GNN). It is suitable as a local model server prototype.

Run locally (recommended inside a venv):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 4000 --workers 1
```

Example request:

```bash
curl -s -X POST http://localhost:4000/score -H 'Content-Type: application/json' \
  -d '{"tenantId":"t1","email":"test@mailinator.com","isNewTenant":true}'
```

Response example:

```json
{"score":0.73,"action":"block","reasons":["disposable_email_domain","new_tenant","ensemble_v1"]}
```

Replace the placeholder `gnn_score` with a real GNN inference (ONNX/TorchScript) and the
heuristic with an XGBoost/LightGBM/TF model for production.
