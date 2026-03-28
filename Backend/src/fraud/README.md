Fraud scoring service

This module provides a fast, lightweight fraud-scoring service used by payment flows.

Key points:
- `FraudService.scorePayment()` returns a `{ score, action, reasons }` object.
- Decisions are produced with a low-latency heuristic and a small set of DB-backed signals.
- The service is intended as a scaffold to integrate production ML models (ONNX/Triton) or external scoring APIs.

Integration:
- Import `FraudModule` into your application module and inject `FraudService` into payment flows.
