# Ghost Data Still Exists — deletion audit agent

This repository contains a deterministic Python agent that audits each request against participant-facing identity, policy, activity, and evidence files. It writes the required root-level `output.csv` and does not call an external model or service.

## Run

Python 3.10 or newer is recommended. From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r code\requirements.txt
.venv\Scripts\python.exe code\main.py
```

The optional `--requests`, `--output`, and `--data` arguments support evaluation on the public sample without overwriting the final output:

```powershell
.venv\Scripts\python.exe code\main.py --requests dataset\sample_deletion_requests.csv --output $env:TEMP\sample_predictions.csv
```

The agent scans the evidence files once per run, then processes requests in memory. It uses only the standard library, pypdf for PDF text, and RapidOCR/ONNX Runtime for offline screenshot OCR. Successful OCR text is cached outside the repository using the image content and RapidOCR version, so repeat runs avoid rescanning unchanged images. Evidence progress, OCR starts, cache hits, and failures are logged; failed extraction is never treated as proof that data is absent. If RapidOCR fails, the agent tries the optional Tesseract fallback when installed.

## Architecture

`code/main.py` contains the pipeline:

1. Load the request, identity, audit-history, activity, evidence-manifest, and deletion-rule tables.
2. Build a current and historical identifier index by stable `user_id`. Email matching is case-insensitive; name similarity is not used to join people.
3. Extract observations from JSON snapshots/exports, SQLite-compatible SQL snapshots, structured and plain-text logs, PDFs, and screenshots. Structured records use deterministic parsing; OCR is local and optional.
4. Resolve resources through exact identifiers, explicit catalog links, and resource-level ownership. A secondary event can link only when an in-cutoff evidence observation exists, an explicitly owned primary-profile event anchors the workflow, and that event is the unique closest candidate for its system and operation. Conflicting explicit owners block the link; event results are never treated as state evidence.
5. Filter evidence by `audit_at`, keep the newest observation per resource, apply `deletion_rules.csv`, and detect active connector and restore paths. A category without a supplied deletion rule is not automatically deleted; it leaves the case unresolved and is reported as a warning. Already-absent flows/backups and `RETAIN` categories do not receive destructive actions.
6. Produce findings, ordered proposed remediation, and verification checks. For an INCOMPLETE case, an account absence check is planned only when an explicitly single-owner evidence record directly linked to the subject contains that account resource ID. Only evidence-backed findings and COMPLETE verifications cite evidence; proposed future actions use an empty `evidence_id`.
7. Write one CSV row per input request, sorted by `case_id`, with valid compact JSON in `steps_json`.

No mutation is performed against any source system. Remediation steps are recommendations, not claims that actions have already been run. NOT_APPLICABLE requests receive `[]`.

## Evaluation and tests

Run the public-sample comparison and output-contract checks:

```powershell
.venv\Scripts\python.exe code\evaluation\main.py
```

Run the local regression cases:

```powershell
Push-Location code
..\.venv\Scripts\python.exe -m unittest test_agent -v
Pop-Location
```

The evaluator compares the 32 public sample rows with `dataset/sample_output.csv`; it does not read organizer-only data. The full 518-case hidden canonical labels are not included in the checkout, so hidden-set accuracy cannot be measured locally. Evaluation details and known failures are in `code/evaluation/evaluation_report.md`.

## Output

The submission schema is exactly `case_id,deletion_status,steps_json`. `steps_json` objects use only the challenge's allowed fields, phases, operations, and states. Steps are numbered consecutively and sorted by phase, operation order, system, and resource.

## Limitations

- OCR and PDF extraction depend on the listed packages; the code logs files that yield no typed resource identifiers for manual review.
- The supplied records can be incomplete or conflicting. Ambiguous OCR identity contexts are excluded unless a unique explicit catalog owner resolves them. Linked categories without a supplied policy are left without proposed action and keep the case INCOMPLETE. The allowed output schema has no dedicated `UNKNOWN` status.
- The program emits findings only when it can connect an observation to an identity using supported identifiers or a catalog link. It does not guess identity from similar names or from the reported workflow status.
- Some public sample resources have no identity-bearing source record and are not linked unless a corroborating identity anchor exists. This conservative rule can miss sample-key actions whose only association is event timing; measured scores and status mismatches are documented without using sample answers in production logic.

## Package for submission

From the repository root, create `code.zip` with the root README and code directory only. Exclude `dataset/`, `.venv/`, `__pycache__/`, and build caches. Keep `code/evaluation/evaluation_report.md` and `code/evaluation/usage_report.md` in the archive.
