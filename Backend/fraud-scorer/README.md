fraud-scorer
=================

Tiny, dependency-free fraud scoring microservice used for fast local scoring and smoke-tests.

Usage

Start the service:

```bash
node index.js
```

Score a payment (example):

```bash
curl -s -X POST http://localhost:3001/score -H 'Content-Type: application/json' \
  -d '{"tenantId":"t1","email":"test@mailinator.com","isNewTenant":true}'
```

Response:

```json
{"score":0.68,"action":"challenge","reasons":["disposable_email_domain","new_tenant"]}
```

This service is intentionally minimal: replace the `score()` implementation with a production model
(ONNX/TensorRT/triton or external scoring API) for higher accuracy and graph-based signals.
