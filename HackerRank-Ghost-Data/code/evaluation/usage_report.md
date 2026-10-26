# Usage and cost report

## Final full-dataset run

- Date: 2026-10-25 (Asia/Calcutta)
- Command: `..\..\.venv\Scripts\python.exe main.py` from the `code` directory
- Requests processed: 518
- Output: repository-root `output.csv`
- Latest warm-cache runtime: approximately 6.0 seconds (about 0.012 seconds per request), with all 11 image OCR results served from cache
- First OCR-cache population run: approximately 59 seconds; RapidOCR took about 4.3–8.1 seconds per image. Cache keys use image content and RapidOCR package version.
- Public evaluation with the populated cache completed in under 2 seconds.
- Output contract validation returned 0 errors. The output contains 518 rows.

The OCR cache is stored in the operating-system temporary directory, outside the repository and submission archive. Changed image content or a changed RapidOCR version triggers a fresh OCR extraction. Progress messages show evidence scanning, OCR starts, cache hits, and completions. Cached text goes through the same evidence parser as a fresh OCR result. On the latest run, two images produced ambiguous identity context; those warnings were logged and the ambiguous identities were not assigned to resources.

## Model and token accounting

| Component | Provider / model | Calls | Input tokens | Output tokens | Cost |
|---|---|---:|---:|---:|---:|
| Language model | None | 0 | 0 | 0 | $0.00 |
| OCR | RapidOCR with ONNX Runtime, local CPU | 11 image extractions on cache population; 11 cache reads on latest run | Not applicable | Not applicable | $0.00 |
| PDF extraction | pypdf, local CPU | 4 files | Not applicable | Not applicable | $0.00 |

No prompts or API requests were sent. LLM input tokens, output tokens, total tokens, and average tokens per request are all **0**. Estimated LLM cost is **$0.00 total** and **$0.00 per request**. OCR processes pixels and emits text; it does not use an LLM token meter. Local CPU time is not included in model/API cost. No paid or hosted service is required.
