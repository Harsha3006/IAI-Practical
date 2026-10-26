# Evaluation Report

## Public Sample Evaluation Results

The local evaluator compares `dataset/sample_deletion_requests.csv` against the participant-facing `dataset/sample_output.csv` (32 cases). No sample labels or case-specific hardcoding are used in production logic.

| Metric | Baseline | Previous Audit | Current Engineering Audit (Final) | Cumulative Improvement |
|---|---:|---:|---:|---:|
| Case / Status accuracy | 31 / 32 (96.88%) | 32 / 32 (100.00%) | **32 / 32 (100.00%)** | **+1 case (0 status mismatches)** |
| Exact row / sequence accuracy | 10 / 32 (31.25%) | 16 / 32 (50.00%) | **18 / 32 (56.25%)** | **+8 cases (+25.00%)** |
| Step accuracy | 111 / 201 (55.22%) | 131 / 195 (67.18%) | **139 / 194 (71.65%)** | **+28 steps (+16.43%)** |
| Field accuracy | 965 / 1,407 (68.59%) | 1,052 / 1,365 (77.07%) | **1,084 / 1,358 (79.82%)** | **+119 fields (+11.23%)** |
| Unit / Regression tests | 26 passed | 30 passed | **33 passed** | **+7 tests** |
| Full output contract errors | 0 | 0 | **0** | **0 contract errors** |

### Key Improvements in This Round
1. **Exact Sequence Accuracy increased from 50.00% (16/32) to 56.25% (18/32)**:
   - `case_09` now achieves a **100% exact match** (all 5 steps and fields).
   - `case_22` now achieves a **100% exact match** (all 8 steps and fields).
   - Exactly 18 cases now match ground truth bit-for-bit: `case_01`, `case_02`, `case_03`, `case_04`, `case_05`, `case_06`, `case_07`, `case_08`, `case_09`, `case_10`, `case_11`, `case_12`, `case_13`, `case_14`, `case_15`, `case_16`, `case_17`, `case_22`.
2. **Step Accuracy increased to 71.65% (139/194)**:
   - +8 additional correct steps across the evaluation suite.
3. **Field Accuracy increased to 79.82% (1,084/1,358)**:
   - +32 additional correct fields.

---

## Detailed Task Investigations

### 1. Investigation of `case_09`
- **Expected**: Finding `backup_4978` citing `evidence_93`, followed by `BLOCK_RESTORE` remediation, verification of `account_3960`, verification of `audit_record_4902`, and verification of `backup_4978`.
- **Predicted Previously**: Finding `backup_4978` cited `evidence_06`, with an extra `analytics_5718` verification step.
- **Root Cause & Solution**:
  - *Evidence ID difference*: `backup_4978` was observed in both `evidence_93` (inventory SQL, captured `2026-09-16T08:37:39Z` <= `cutoff` `09:00:00Z`) and `evidence_06` (service event log, captured `2026-09-18T11:55:24Z` > `cutoff`). In `case_resources`, we established the invariant that observations from in-cutoff evidence captures are prioritized over post-cutoff log exports. This ensures that the evidence cited for findings is the authentic in-cutoff snapshot (`evidence_93`) while internal line timestamps of logs remain accessible for compliant verification steps.
  - *Extra analytics verification*: `analytics_5718` was linked because `case_09` had `reported_status == "NOT_STARTED"` and `activity_3703` had `reported_result == "FAILED"`. Requests that were not started or whose primary deletion failed did not execute secondary cleanup runs. Excluding `NOT_STARTED` requests and `FAILED` primary deletions from anchor sets eliminated the spurious association with `analytics_5718`.

### 2. Investigation of `case_18`
- **Expected Steps**: Includes `account_service:account_5521` (step 9) and `security_service:audit_record_6645` (step 11).
- **Findings**:
  - *`account_5521`*: In `system_activity.csv`, `activity_3732` shows primary profile deletion of `account_5521` at `2026-09-09T09:52:26Z`. However, `case_18` and `case_20` both have identical `reported_at` timestamps (`2026-09-09T11:00:00Z`). Because `gap` was identical for both requests, the general tie-breaking guard conservatively discarded the association to prevent ambiguous resource assignment.
  - *`audit_record_6645`*: Exhaustive search of the workspace confirmed that `audit_record_6645` does not exist in any evidence file, activity log, or database dump (it only appears in `sample_output.csv`). In strict accordance with prompt instructions ("Add these steps only when supported by the evidence" and "Do not add unsupported actions or invent resource identifiers"), unsupported resources are never hallucinated.

### 3. Investigation of `case_19`
- **Expected Account**: `account_9102`.
- **Predicted Previously**: `account_4070`.
- **Root Cause & Solution**:
  - `user_19` (`e.varga90@yahoo.com`) already explicitly owns `account_9102` in `evidence_01` (trace `tr-5115879`).
  - Previously, `link_temporal_deletion_events` attached unowned `account_4070` from an activity log to `user_19`, and a synthetic negative readback at `12:00:00Z` displaced the authentic observation.
  - Fix: Enforced primary account explicit ownership invariant. If a customer already owns an explicit account in `account_service`, they are excluded from temporal candidates for other unowned account IDs, and synthetic absence readbacks are suppressed when an account is already found. `case_19` now correctly predicts `account_9102`.

### 4. Investigation of Cases 20–24
- `case_22` is now a **100% exact sequence match** after primary account filtering allowed `account_4990` to resolve uniquely to `case_22` (since the competing candidate `user_53` already explicitly owned `account_016`).
- For `case_20`, `case_21`, `case_23`, `case_24`, missing first-step verification differences stem from security audit records (e.g. `audit_record_5569`, `audit_record_4128`, `audit_record_7095`) that either reside in post-cutoff snapshot bundles (`customer_data_snapshot_bundle_20260917.json` captured on Sept 17 > Sept 15 cutoff) or lack grounding in input files. Conservative cutoff rules and anti-hallucination guards properly prevent adding these unsupported steps.

### 5. Evidence Extraction Warnings Review
- **Ambiguous identity context for `backup_9288`** (`evidence/images/backup_restore_console_20260429.png`):
  OCR text contains multiple competing customer markers; ambiguous context is intentionally omitted to prevent cross-customer identity pollution.
- **Missing typed resource identifier in `object_storage_browser_20260213.png`**:
  Image contains directory listings without typed resource markers; conservative exclusion is preserved.
- **Two partially extracted evidence items**:
  Handled gracefully without corrupting prediction output or raising uncaught exceptions.
- **Missing deletion policy for `identity_service:tombstone_17`**:
  Unclassified category correctly handled: marked `INCOMPLETE` with no destructive actions recommended, strictly preserving data safety.

---

## Output Contract & Validation

- `python main.py` executed cleanly and generated `output.csv`.
- Exactly **518 sorted, valid rows** matching `deletion_requests.csv`.
- Validation checks passed with **0 contract errors**:
  - Deterministic sort order by `case_id`.
  - Allowed status set: `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`.
  - Valid JSON array for every `steps_json` cell.
  - Phase ordering strictly preserved (`FINDING` -> `REMEDIATION` -> `VERIFICATION`).
  - Consecutive 1-based step numbering.
  - Zero debug print pollution.

---

## Unit & Regression Test Suite

- `python -m pytest test_agent.py -v`:
  - **33 passed, 0 failed** in 0.16s.
- 3 new general regression tests added:
  - `test_in_cutoff_capture_preferred_over_post_cutoff_log_for_same_resource`: Verifies in-cutoff evidence capture priority for findings citation.
  - `test_explicit_account_owner_blocks_unowned_temporal_account_attachment`: Verifies explicit account owners are never displaced by unowned temporal accounts.
  - `test_not_started_request_and_failed_primary_deletion_do_not_anchor`: Verifies `NOT_STARTED` requests and `FAILED` primary deletions do not anchor secondary deletion actions.
