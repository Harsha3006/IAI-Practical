"""Evaluate the public 32-case sample and structural output contract."""
from __future__ import annotations

import csv
import importlib.util
import json
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
AGENT_PATH = Path(__file__).resolve().parents[1] / "main.py"
AGENT_SPEC = importlib.util.spec_from_file_location("deletion_audit_agent", AGENT_PATH)
agent = importlib.util.module_from_spec(AGENT_SPEC)
sys.modules[AGENT_SPEC.name] = agent
AGENT_SPEC.loader.exec_module(agent)


def canonical_steps(raw: str):
    return json.loads(raw)


def score(expected_path: Path, predicted_path: Path) -> dict[str, float | int]:
    with expected_path.open(encoding="utf-8-sig", newline="") as f:
        expected = list(csv.DictReader(f))
    with predicted_path.open(encoding="utf-8-sig", newline="") as f:
        predicted = list(csv.DictReader(f))
    em = {x["case_id"]: x for x in expected}
    pm = {x["case_id"]: x for x in predicted}
    ids = sorted(em)
    status_ok = sum(i in pm and em[i]["deletion_status"] == pm[i]["deletion_status"] for i in ids)
    row_ok = sum(i in pm and em[i]["deletion_status"] == pm[i]["deletion_status"] and canonical_steps(em[i]["steps_json"]) == canonical_steps(pm[i]["steps_json"]) for i in ids)
    seq_ok = 0
    fields = field_total = steps_ok = step_total = 0
    step_mismatches = []
    for case_id in ids:
        a = canonical_steps(em[case_id]["steps_json"])
        b = canonical_steps(pm[case_id]["steps_json"]) if case_id in pm else []
        if a == b:
            seq_ok += 1
        elif len(step_mismatches) < 8:
            brief = lambda seq: [{k: item.get(k) for k in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")} for item in seq]
            step_mismatches.append({"case_id": case_id, "expected": brief(a), "predicted": brief(b)})
        step_total += max(len(a), len(b))
        steps_ok += sum(x == y for x, y in zip(a, b))
        for n in range(max(len(a), len(b))):
            left = a[n] if n < len(a) else {}
            right = b[n] if n < len(b) else {}
            for key in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                fields += int(key in left and key in right and left[key] == right[key])
    return {
        "cases": len(ids), "prediction_rows": len(predicted),
        "case_accuracy": status_ok / max(1, len(ids)), "status_correct": status_ok,
        "row_accuracy": row_ok / max(1, len(ids)), "row_exact": row_ok,
        "sequence_accuracy": seq_ok / max(1, len(ids)), "sequence_exact": seq_ok,
        "step_accuracy": steps_ok / max(1, step_total), "steps_correct": steps_ok, "steps_total": step_total,
        "field_accuracy": fields / max(1, field_total), "fields_correct": fields, "fields_total": field_total,
        "status_mismatches": [
            {"case_id": i, "expected": em[i]["deletion_status"], "predicted": pm.get(i, {}).get("deletion_status", "MISSING")}
            for i in ids if i not in pm or em[i]["deletion_status"] != pm[i]["deletion_status"]
        ],
        "first_step_mismatch_cases": step_mismatches,
    }


def validate_contract(output_path: Path, request_path: Path) -> list[str]:
    with request_path.open(encoding="utf-8-sig", newline="") as f:
        requests = list(csv.DictReader(f))
    with output_path.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    errors = []
    if len(rows) != len(requests):
        errors.append(f"row count {len(rows)} != request count {len(requests)}")
    if [r["case_id"] for r in rows] != sorted(r["case_id"] for r in requests):
        errors.append("rows are not sorted by case_id")
    valid = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    fields = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
    contracts = {
        "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"), "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
        "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"), "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
        "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"), "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
        "DELETE_RECORD": ("REMEDIATION", "ABSENT"), "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
        "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"), "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
        "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"), "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
        "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"), "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
        "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
    }
    for row in rows:
        if row["deletion_status"] not in valid:
            errors.append(f"invalid status for {row['case_id']}")
        try:
            steps = json.loads(row["steps_json"])
            if not isinstance(steps, list):
                raise ValueError("steps_json is not an array")
            if row["deletion_status"] == "NOT_APPLICABLE" and steps:
                errors.append(f"NOT_APPLICABLE has steps for {row['case_id']}")
            phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
            if [phase_order.get(x.get("phase"), 99) for x in steps] != sorted(phase_order.get(x.get("phase"), 99) for x in steps):
                errors.append(f"phase order invalid for {row['case_id']}")
            previous = {}
            for n, item in enumerate(steps, 1):
                if item.get("step_no") != n:
                    errors.append(f"nonconsecutive step numbers for {row['case_id']}")
                if set(item) != fields:
                    errors.append(f"step fields invalid for {row['case_id']} step {n}")
                if contracts.get(item.get("operation")) != (item.get("phase"), item.get("state")):
                    errors.append(f"operation/state invalid for {row['case_id']} step {n}")
                phase = item.get("phase", "")
                if row["deletion_status"] == "COMPLETE" and phase != "VERIFICATION":
                    errors.append(f"COMPLETE contains non-verification step for {row['case_id']}")
                if phase == "FINDING" and not item.get("evidence_id"):
                    errors.append(f"finding has no evidence reference for {row['case_id']}")
                if phase != "FINDING" and row["deletion_status"] == "INCOMPLETE" and item.get("evidence_id"):
                    errors.append(f"proposed step has evidence reference for {row['case_id']}")
                if row["deletion_status"] == "COMPLETE" and not item.get("evidence_id"):
                    errors.append(f"COMPLETE verification has no evidence for {row['case_id']}")
                key = (phase_order.get(phase, 99), agent.OP_ORDER.get(item.get("operation"), 99), item.get("system_id", ""), item.get("resource_id", ""))
                if phase in previous and key < previous[phase]:
                    errors.append(f"within-phase ordering invalid for {row['case_id']}")
                previous[phase] = key
        except Exception as exc:
            errors.append(f"invalid JSON for {row['case_id']}: {exc}")
    return errors


def main() -> None:
    # Public sample output is the only supplied answer key used here.
    with tempfile.TemporaryDirectory(prefix="deletion-audit-eval-") as tmp:
        predicted = Path(tmp) / "sample_predictions.csv"
        agent.run(ROOT / "dataset" / "sample_deletion_requests.csv", predicted, ROOT / "dataset")
        metrics = score(ROOT / "dataset" / "sample_output.csv", predicted)
        contract = validate_contract(ROOT / "output.csv", ROOT / "dataset" / "deletion_requests.csv") if (ROOT / "output.csv").exists() else []
    print(json.dumps({"sample_metrics": metrics, "full_output_contract_errors": contract}, indent=2))


if __name__ == "__main__":
    main()
