Document Processing Module
=========================

This module provides a pluggable pipeline for OCR + NLP extraction with a human-in-the-loop review path.

Features implemented:
- File upload endpoint: `POST /documents/upload` (multipart form `file`)
- Status endpoint: `GET /documents/:id/status`
- Result endpoint: `GET /documents/:id/result`
- Human verification: `POST /documents/:id/verify`
- OCR adapter that calls `tesseract` CLI when available, with fallbacks.
- Simple heuristic extractors for dates, amounts, names, clauses, and signatures.
- Audit trail files written to the document store (and Prisma models added).

Notes:
- In production, set `DOC_STORE_DIR` to a secure storage path and back it up.
- For higher OCR accuracy use cloud providers (AWS Textract, Google Vision, Azure Form Recognizer).
- Replace heuristic extractors with ML/NLP models (spaCy, transformer-based NER) for robust extraction.
