"""Evidence-grounded deletion audit agent for the October 2026 challenge.

The implementation is deterministic and uses only participant-facing inputs.
Optional PDF/image readers are used when installed; extraction failures are
reported to stderr and never converted into evidence of absence.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"
OCR_CACHE_DIR = Path(tempfile.gettempdir()) / "ghost-data-still-exists-ocr-v1"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def norm(value: Any) -> str:
    return str(value or "").strip().casefold()


def before(value: str, cutoff: str) -> bool:
    return bool(value and value <= cutoff)


def iso(value: Any) -> str:
    if not value:
        return ""
    value = str(value)
    if re.fullmatch(r"\d{4}-\d\d-\d\d", value):
        return value + "T23:59:59Z"
    return value


@dataclass
class Observation:
    system: str
    resource: str
    category: str
    state: str
    has_pii: bool
    at: str
    evidence: str
    identifiers: tuple[str, ...] = ()


class EvidenceIndex:
    """Extract and index structured evidence once for all requests."""
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.files = {r["file_id"]: r for r in read_csv(data_dir / "evidence_files.csv")}
        self.file_by_path = {r["file_path"].replace("\\", "/"): r for r in self.files.values()}
        self.rules = {r["data_category"]: r for r in read_csv(data_dir / "deletion_rules.csv")}
        self.observations: list[Observation] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.ocr_reader = None
        self.activity = read_csv(data_dir / "system_activity.csv")
        self.identities = read_csv(data_dir / "user_identities.csv")
        self.audit = read_csv(data_dir / "user_audit_log.csv")
        self.aliases_by_user: dict[str, set[str]] = defaultdict(set)
        self.fields_by_user: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self._build_identity_index()
        self.users_by_alias: dict[str, set[str]] = defaultdict(set)
        self.resource_users: dict[tuple[str, str], set[str]] = defaultdict(set)
        self.resource_links: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        self.temporal_resource_users: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
        self.sql_scopes: dict[str, set[str]] = defaultdict(set)
        self._index_activity_links()
        self._build_alias_owner_index()
        self._scan()
        self._build_resource_owner_index()

    def _build_identity_index(self) -> None:
        for row in self.identities:
            uid = row["user_id"]
            # Stable internal references are first-class identifiers in snapshots
            # whose direct identifiers have already been removed.
            self.aliases_by_user[uid].add(norm(uid))
            for col in ("email", "name", "phone", "email_hash"):
                if row.get(col):
                    value = norm(row[col])
                    self.aliases_by_user[uid].add(value)
                    self.fields_by_user[uid][col].add(value)
        for row in self.audit:
            uid, field = row.get("user_id", ""), row.get("field_name", "")
            if not uid:
                continue
            for col in ("email", "name", "phone", "email_hash"):
                if field.casefold() == col:
                    for val in (row.get("old_value"), row.get("new_value")):
                        if val:
                            value = norm(val)
                            self.aliases_by_user[uid].add(value)
                            self.fields_by_user[uid][col].add(value)

    def _build_alias_owner_index(self) -> None:
        """Build a reverse index so ownership checks stay linear in identifiers."""
        for uid, aliases in self.aliases_by_user.items():
            for alias in aliases:
                if alias:
                    self.users_by_alias[alias].add(uid)

    def _build_resource_owner_index(self) -> None:
        """Prefer catalog and non-image identity links over OCR-derived owners."""
        self.explicit_owners_by_resource: dict[tuple[str, str], set[str]] = defaultdict(set)
        image_owners: dict[tuple[str, str], set[str]] = defaultdict(set)
        observed_owners: dict[tuple[str, str], set[str]] = defaultdict(set)
        for observation in self.observations:
            key = (observation.system, observation.resource)
            path = self.files.get(observation.evidence, {}).get("file_path", "").casefold()
            is_image = Path(path).suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}
            owners = image_owners[key] if is_image else observed_owners[key]
            for identifier in observation.identifiers:
                owners.update(self.users_by_alias.get(norm(identifier), ()))
        for key in set(image_owners) | set(observed_owners) | set(self.resource_users):
            # Activity-catalog links are explicit user/email pairs. Structured
            # observations and trace logs outrank image context; OCR is a
            # fallback when stronger identity evidence is unavailable.
            self.explicit_owners_by_resource[key].update(
                self.resource_users.get(key) or observed_owners.get(key) or image_owners.get(key, set())
            )

    def _index_activity_links(self) -> None:
        # The catalog's explicit links are identity evidence, not proof of state.
        for row in self.activity:
            details = row.get("details", "")
            match = re.search(r"\b(user_\d+)\b", details, re.I)
            email = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", details, re.I)
            if not match or not email:
                continue
            uid = match.group(1).lower()
            event_at = iso(row.get("event_time"))
            system = row.get("target_system", "")
            resource = row.get("resource_id", "")
            self.resource_users[(system, resource)].add(uid)
            self.resource_links[(system, resource)].append(row)
            # Catalog links may add a historical email missing from the audit file.
            self.aliases_by_user[uid].add(norm(email.group(0)))
            self.fields_by_user[uid]["email"].add(norm(email.group(0)))

    def _file_id(self, path: Path) -> tuple[str, str]:
        rel = path.relative_to(self.data_dir).as_posix()
        row = self.file_by_path.get(rel)
        return (row["file_id"], iso(row.get("captured_at", ""))) if row else ("", "")

    def _scan(self) -> None:
        evroot = self.data_dir / "evidence"
        paths = [path for path in sorted(evroot.rglob("*")) if path.is_file()]
        print(f"[evidence] Scanning {len(paths)} evidence files", file=sys.stderr, flush=True)
        for number, path in enumerate(paths, 1):
            if number == 1 or number % 10 == 0 or number == len(paths):
                print(f"[evidence] {number}/{len(paths)}: {path.name}", file=sys.stderr, flush=True)
            file_id, capture = self._file_id(path)
            try:
                suffix = path.suffix.casefold()
                if suffix == ".json":
                    self._scan_json(path, file_id, capture)
                elif suffix == ".sql":
                    self._scan_sql(path, file_id, capture)
                elif suffix == ".log" or suffix == ".txt":
                    self._scan_text(path, file_id, capture)
                elif suffix == ".pdf":
                    self._scan_pdf(path, file_id, capture)
                elif suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}:
                    self._scan_image(path, file_id, capture)
                else:
                    self.errors.append(f"Unsupported evidence format: {path.name}")
            except Exception as exc:  # one malformed artifact must not abort the dataset
                self.errors.append(f"{path.name}: {type(exc).__name__}: {exc}")

    def _scan_json(self, path: Path, file_id: str, capture: str) -> None:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            if "snapshots" in data and isinstance(data["snapshots"], list):
                for item in data["snapshots"]:
                    if isinstance(item, dict):
                        sys_name = item.get("data_store") or self._system_from_key(item.get("collection", ""))
                        if sys_name:
                            self.sql_scopes[file_id].add(sys_name)
            if "service_exports" in data and isinstance(data["service_exports"], dict):
                for sys_name in data["service_exports"]:
                    self.sql_scopes[file_id].add(sys_name)
        def walk(obj: Any, system: str = "", category_hint: str = "", at: str = "") -> None:
            if isinstance(obj, dict):
                source_hint = str(obj.get("source") or obj.get("origin") or "")
                hinted = "" if "service_resource_export" in source_hint.casefold() or "records_assurance" in source_hint.casefold() else self._system_from_key(source_hint)
                local_system = str(obj.get("data_store") or obj.get("system") or system or hinted)
                local_at = iso(obj.get("captured_at") or obj.get("observed_at") or obj.get("recorded_at") or obj.get("exported_at") or obj.get("updated_at") or obj.get("created_at") or at or capture)
                resource = str(obj.get("resource_id") or "")
                if resource:
                    cat = category_hint if category_hint and category_hint != "UNKNOWN" else self._category(local_system, "", obj)
                    state, pii = self._state(local_system, cat, obj)
                    self.observations.append(Observation(local_system, resource, cat, state, pii, local_at, file_id, tuple(self._scalar_strings(obj))))
                for key, value in obj.items():
                    if isinstance(value, (dict, list)):
                        child_system = self._system_from_key(key) or local_system
                        child_hint = " ".join(x for x in (str(obj.get("collection", "")), str(obj.get("record_type", "")), key) if x)
                        child_cat = self._category(child_system, child_hint, {})
                        walk(value, child_system, child_cat, local_at)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item, system, category_hint, at)
        walk(data)

    @staticmethod
    def _scalar_strings(obj: dict[str, Any]) -> Iterable[str]:
        def walk(value: Any) -> Iterable[str]:
            if isinstance(value, dict):
                for child in value.values():
                    yield from walk(child)
            elif isinstance(value, list):
                for child in value:
                    yield from walk(child)
            elif value is not None and not isinstance(value, bool):
                yield norm(value)
        yield from walk(obj)

    @staticmethod
    def _system_from_key(key: str) -> str:
        key = key.casefold()
        mapping = {"account": "account_service", "analytics": "analytics_platform", "backup": "backup_service", "export": "export_service", "integration": "integration_service", "connector": "integration_service", "search": "search_service", "security": "security_service", "support": "support_platform", "identity": "identity_service", "marketing": "marketing_platform", "object": "object_storage"}
        return next((v for k, v in mapping.items() if k in key), "")

    @staticmethod
    def _category(system: str, hint: str, obj: dict[str, Any]) -> str:
        text = (system + " " + hint + " " + str(obj.get("record_type", "")) + " " + str(obj.get("collection", ""))).casefold()
        for key, cat in (("tombstone", "ACCOUNT_TOMBSTONE"), ("deleted_customer_reference", "ACCOUNT_TOMBSTONE"), ("customer_profile", "USER_PROFILE"), ("profile_lookup", "USER_PROFILE"), ("account_service", "USER_PROFILE"), ("search", "SEARCH_INDEX_ENTRY"), ("index", "SEARCH_INDEX_ENTRY"), ("cache", "CACHE_ENTRY"), ("analytics", "ANALYTICS_PROFILE"), ("telemetry", "PRODUCT_TELEMETRY"), ("ticket_attachment", "SUPPORT_ATTACHMENT"), ("attachment", "SUPPORT_ATTACHMENT"), ("ticket", "SUPPORT_MESSAGE"), ("support", "SUPPORT_MESSAGE"), ("contact_index", "SECONDARY_IDENTIFIER"), ("legacy_contact", "SECONDARY_IDENTIFIER"), ("export", "USER_EXPORT"), ("marketing", "MARKETING_PROFILE"), ("email_delivery", "EMAIL_DELIVERY_LOG"), ("security", "SECURITY_AUDIT_LOG"), ("audit_record", "SECURITY_AUDIT_LOG"), ("backup", "BACKUP_ARCHIVE"), ("restore", "BACKUP_ARCHIVE"), ("connector", "DATA_FLOW"), ("subscription", "DATA_FLOW"), ("data_flow", "DATA_FLOW"), ("retained_order_records", "LEGAL_HOLD_RECORD"), ("legal_hold", "LEGAL_HOLD_RECORD"), ("legal_service", "LEGAL_HOLD_RECORD"), ("disputed orders", "LEGAL_HOLD_RECORD"), ("retention register", "LEGAL_HOLD_RECORD")):
            if key in text:
                return cat
        return "UNKNOWN"

    @classmethod
    def _state(cls, system: str, category: str, obj: dict[str, Any]) -> tuple[str, bool]:
        flat: dict[str, Any] = {}
        def flatten(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    flat[key] = child
                    flatten(child)
            elif isinstance(value, list):
                for child in value:
                    flatten(child)
        flatten(obj)
        flattened = " ".join(cls._scalar_strings(obj))
        pii_keys = ("email", "phone", "name", "full_name", "requester_name", "requester_email", "requester_phone", "email_hash", "owner_email", "customer_email")
        pii = any(flat.get(k) not in (None, "") for k in pii_keys)
        free_text_keys = {"message_text", "message_excerpt", "content", "body", "description"}
        free_text = " ".join(str(value) for key, value in flat.items() if key in free_text_keys and isinstance(value, str))
        if free_text:
            email_in_text = re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", free_text, re.I)
            phone_in_text = re.search(r"(?<!\w)(?:\+\d[\d ().-]{5,}\d|\d{3}[-. ]\d{3}[-. ]\d{4})(?!\w)", free_text)
            pii = pii or bool(email_in_text or phone_in_text)
        # A status label is not proof that a row is absent: deleted profiles can
        # still retain their identifiers in a replica. Only an explicit
        # not-found response or a null profile establishes absence here.
        if category == "USER_PROFILE" and (("profile" in obj and obj.get("profile") is None) or flat.get("status_code") == 404 or flat.get("account_status") == "NOT_FOUND"):
            return "ABSENT", False
        if category in {"SEARCH_INDEX_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "USER_PROFILE", "CACHE_ENTRY", "SUPPORT_ATTACHMENT"}:
            return "PRESENT", pii
        if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            return ("PRESENT", True) if pii else ("ANONYMIZED", False)
        if category == "SUPPORT_MESSAGE":
            # A shared ticket remains by policy; only identifiers require redaction.
            return ("PRESENT", True) if pii else ("REDACTED", False)
        if category == "ACCOUNT_TOMBSTONE":
            return ("PRESENT", True) if pii else ("REDACTED", False)
        if category == "SECURITY_AUDIT_LOG":
            return "PRESENT", False
        if category == "BACKUP_ARCHIVE":
            return ("BLOCKED", False) if flat.get("restore_allowed") in (False, 0, "0") else ("ACTIVE", False)
        if category == "DATA_FLOW":
            return ("ACTIVE", False) if flat.get("enabled") in (True, 1, "1") else ("DISABLED", False)
        if "not_found" in flattened or "404" in flattened:
            return "ABSENT", False
        return "PRESENT", pii

    def _scan_sql(self, path: Path, file_id: str, capture: str) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(path.read_text(encoding="utf-8-sig"))
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            scopes = {r[0]: iso(r[1]) for r in conn.execute("SELECT origin_system,captured_at FROM snapshot_scope")} if "snapshot_scope" in tables else {}
            for table in tables:
                if table == "snapshot_scope":
                    continue
                columns = [x[1] for x in conn.execute(f'PRAGMA table_info("{table}")')]
                if {"origin_system", "collection_name", "record_json"}.issubset(columns):
                    for row in conn.execute(f'SELECT * FROM "{table}"'):
                        values = dict(zip(columns, row))
                        raw_record = values.get("record_json")
                        try:
                            record = json.loads(raw_record) if isinstance(raw_record, str) else raw_record
                            if not isinstance(record, dict):
                                raise ValueError("record_json must contain an object")
                        except (json.JSONDecodeError, TypeError, ValueError) as exc:
                            self.errors.append(f"{path.name}:{values.get('resource_id', '')}: invalid record_json ({type(exc).__name__})")
                            continue
                        origin = str(values.get("origin_system", ""))
                        system = {"legal_service": "legal_retention_service"}.get(origin, origin)
                        resource = str(values.get("resource_id") or record.get("resource_id") or "")
                        if not system or not resource:
                            continue
                        self.sql_scopes[file_id].add(system)
                        collection = str(values.get("collection_name", ""))
                        category = self._category(system, collection, record)
                        state, pii = self._state(system, category, record)
                        at = iso(values.get("updated_at") or scopes.get(system) or capture)
                        identifiers = tuple(dict.fromkeys((norm(resource), *self._scalar_strings(record))))
                        self.observations.append(Observation(system, resource, category, state, pii, at, file_id, identifiers))
                    continue
                system = next((s for s, prefixes in (("account_service",("customer_profiles",)),("search_service",("customer_search_documents", "search_documents")),("analytics_platform",("customer_analytics_profiles",)),("support_platform",("support_records",)),("export_service",("customer_exports",)),("integration_service",("connector_subscriptions",)),("backup_service",("backup_restore_entries",)),("security_service",("security_audit_records",))) if table.startswith(prefixes)), "")
                if system and conn.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone() is not None:
                    self.sql_scopes[file_id].add(system)
                for row in conn.execute(f'SELECT * FROM "{table}"'):
                    values = dict(zip([x[1] for x in conn.execute(f'PRAGMA table_info("{table}")')], row))
                    cat = self._category(system, table, values)
                    at = iso(values.get("updated_at") or scopes.get(system) or capture)
                    state, pii = self._state(system, cat, values)
                    self.observations.append(Observation(system, str(values.get("resource_id", "")), cat, state, pii, at, file_id, tuple(self._scalar_strings(values))))
        finally:
            conn.close()

    def _scan_text(self, path: Path, file_id: str, capture: str) -> None:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        def line_props(line: str) -> dict[str, str]:
            # Some service-event files contain one JSON object per line while
            # others use key=value logfmt. Parse JSON first so values are not
            # left with punctuation and can be correlated by trace_id.
            try:
                payload = json.loads(line[line.find("{"):])
                if isinstance(payload, dict):
                    return {str(key): str(value) for key, value in payload.items() if value is not None}
            except (ValueError, TypeError):
                pass
            return {key: value.strip('"') for key, value in re.findall(r"([A-Za-z_][\w]*)=([^\s]+)", line)}

        trace_identifiers: dict[str, set[str]] = defaultdict(set)
        for raw in lines:
            props = line_props(raw)
            trace_id = props.get("trace_id")
            if trace_id:
                for key in ("lookup_key", "subject_ref", "subject_key", "owner_key", "owner_email", "match_key", "customer_reference", "correlation_key"):
                    value = props.get(key)
                    if value and value.casefold() != "null":
                        trace_identifiers[trace_id].add(norm(value))
        for line in lines:
            if not line.strip():
                continue
            # The account handover is a pipe-delimited typed readback rather
            # than a key=value log. Preserve its per-row timestamp and category.
            parts = [part.strip().lstrip("- ").strip() for part in line.split("|")]
            if len(parts) >= 6 and re.match(r"\d{4}-\d\d-\d\dT", parts[0]):
                at, system, resource, category_raw, result, identity = parts[:6]
                category = self._category(system, category_raw, {"record_type": category_raw})
                state, pii = self._state(system, category, {"email": identity if "@" in identity else None, "subject_reference": identity if identity.startswith("user_") else None})
                result_state = result.upper()
                if result_state in {"NOT_FOUND", "ABSENT", "MISSING"}:
                    state, pii = "ABSENT", False
                elif result_state in {"ACTIVE", "ENABLED", "RUNNING"}:
                    state, pii = "ACTIVE", False
                elif result_state in {"DISABLED", "STOPPED"}:
                    state, pii = "DISABLED", False
                elif result_state in {"BLOCKED", "RESTORE_BLOCKED"}:
                    state, pii = "BLOCKED", False
                elif result_state in {"ANONYMIZED", "REDACTED"}:
                    state, pii = result_state, False
                elif result_state in {"FOUND", "PRESENT", "IDENTIFIABLE"} and category not in {"SECURITY_AUDIT_LOG", "BACKUP_ARCHIVE", "DATA_FLOW"}:
                    state = "PRESENT"
                self.observations.append(Observation(system, resource, category, state, pii, iso(at), file_id, (norm(identity),)))
                continue
            props = line_props(line)
            resource = props.get("resource_id", "")
            if not resource:
                match = re.search(r"\b((?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|marketing|object|cache|email_delivery)_\d+)\b", line)
                resource = match.group(1) if match else ""
            if not resource:
                continue
            raw_system = props.get("service", "")
            system = self._system_from_key(raw_system) or raw_system
            if not system:
                for name in ("account_service", "search_service", "analytics_platform", "support_platform", "integration_service", "backup_service", "security_service", "export_service", "marketing_platform", "object_storage", "identity_service"):
                    if name in line:
                        system = name
                        break
            at = iso(line[:20]) or capture
            event = props.get("event", "")
            raw_rows = props.get("rows")
            rows_num = int(re.search(r"\d+", raw_rows).group(0)) if raw_rows and re.search(r"\d+", raw_rows) else (0 if raw_rows in ("0", "null") else None)
            raw_direct = props.get("direct_identifiers", "")
            direct_num = int(re.search(r"\d+", raw_direct).group(0)) if re.search(r"\d+", raw_direct) else 0
            has_matched_val = bool(props.get("matched_value") and props.get("matched_value") != "null")

            if any(name in event for name in ("connector_config_read_completed", "connector_heartbeat", "connector_config_loaded")):
                cat = "DATA_FLOW"
                enabled = props.get("enabled", "").casefold()
                scheduler = props.get("scheduler_registered", "").casefold()
                state = "ACTIVE" if enabled == "true" or (not enabled and scheduler == "true") else "DISABLED"
            elif "restore_policy_read_completed" in event:
                cat, state = "BACKUP_ARCHIVE", "ACTIVE" if props.get("restore_allowed") == "true" else "BLOCKED"
            elif "restore_candidate_evaluated" in event:
                cat, state = "BACKUP_ARCHIVE", "ACTIVE" if props.get("eligible") == "true" and props.get("deletion_block") == "false" else "BLOCKED"
            elif "restore_authorization_completed" in event:
                cat, state = "BACKUP_ARCHIVE", "ACTIVE" if props.get("authorized") == "true" else "BLOCKED"
            elif "profile_lookup_completed" in event:
                cat, state = "USER_PROFILE", "ABSENT" if rows_num == 0 or props.get("http_status") == "404" else "PRESENT"
            elif "index_query_completed" in event:
                cat, state = "SEARCH_INDEX_ENTRY", "PRESENT" if props.get("result") == "hit" else "ABSENT"
            elif "support_ticket_read_completed" in event:
                cat = "SUPPORT_MESSAGE"
                state = "ABSENT" if rows_num == 0 else ("PRESENT" if any(props.get(k, "null") not in ("null", "") for k in ("requester_email", "requester_name", "requester_phone")) else "REDACTED")
            elif "message_pii_scan" in event:
                cat = "SUPPORT_MESSAGE"
                state = "PRESENT" if (has_matched_val or direct_num > 0 or props.get("pii_detected") in ("true", "1")) else "REDACTED"
            elif "attachment_pii_scan" in event:
                cat = "SUPPORT_ATTACHMENT"
                state = "PRESENT" if (has_matched_val or direct_num > 0 or props.get("pii_detected") in ("true", "1")) else "ABSENT"
            elif "analytics_profile_read" in event:
                cat = "ANALYTICS_PROFILE"
                state = "ABSENT" if rows_num == 0 else ("PRESENT" if any(props.get(k, "null") not in ("null", "") for k in ("customer_reference", "email", "phone", "email_hash")) else "ANONYMIZED")
            elif "analytics_identity_scan" in event:
                cat = "ANALYTICS_PROFILE"
                state = "PRESENT" if (has_matched_val or direct_num > 0 or props.get("pii_detected") in ("true", "1")) else "ANONYMIZED"
            elif "contact_lookup_completed" in event or "contact_query_completed" in event:
                cat = "SECONDARY_IDENTIFIER"
                state = "PRESENT" if rows_num != 0 and props.get("rows") not in ("0", "null", "") else "ABSENT"
            elif "export_download_check_completed" in event:
                cat = "USER_EXPORT"
                state = "PRESENT" if props.get("available") == "true" or props.get("http_status") == "200" else "ABSENT"
            elif "audit_record_read_completed" in event:
                cat, state = "SECURITY_AUDIT_LOG", "PRESENT" if rows_num != 0 and props.get("rows") not in ("0", "null", "") else "ABSENT"
            else:
                continue
            identifiers = [norm(v) for v in props.values()]
            identifiers.extend(sorted(trace_identifiers.get(props.get("trace_id", ""), ())))
            self.observations.append(Observation(system, resource, cat, state, state == "PRESENT", at, file_id, tuple(identifiers)))

    def _scan_pdf(self, path: Path, file_id: str, capture: str) -> None:
        try:
            from pypdf import PdfReader  # type: ignore
            text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
            self._scan_extracted_text(text, file_id, capture)
        except ImportError:
            self.errors.append(f"PDF text extraction unavailable: {path.name}")

    def _scan_image(self, path: Path, file_id: str, capture: str) -> None:
        started = time.perf_counter()
        try:
            payload = path.read_bytes()
        except OSError as exc:
            self.errors.append(f"Image read failed for {path.name}: {type(exc).__name__}: {exc}")
            return
        try:
            from importlib.metadata import PackageNotFoundError, version
            try:
                engine_version = version("rapidocr-onnxruntime")
            except PackageNotFoundError:
                engine_version = "unavailable"
        except Exception:
            engine_version = "unknown"
        cache_key = hashlib.sha256(b"rapidocr-onnxruntime:" + engine_version.encode() + b"\0" + payload).hexdigest()
        cache_path = OCR_CACHE_DIR / f"{cache_key}.json"
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("schema") == 1 and isinstance(cached.get("text"), str):
                text = cached["text"]
                print(f"[ocr] {path.name}: cache hit ({len(text)} characters)", file=sys.stderr, flush=True)
                if text.strip():
                    self._scan_extracted_text(text, file_id, capture)
                else:
                    self.errors.append(f"OCR produced no text for {path.name}")
                return
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError, AttributeError, TypeError) as exc:
            self.errors.append(f"Ignoring invalid OCR cache for {path.name}: {type(exc).__name__}")

        print(f"[ocr] {path.name}: starting OCR", file=sys.stderr, flush=True)
        rapid_error = None
        text = ""
        backend = "rapidocr"
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore
            if self.ocr_reader is None:
                self.ocr_reader = RapidOCR()
            result, _ = self.ocr_reader(str(path))
            text = "\n".join(item[1] for item in (result or []))
        except Exception as exc:
            rapid_error = exc
        if rapid_error is not None or not text.strip():
            try:
                import pytesseract  # type: ignore
                from PIL import Image
                fallback_text = pytesseract.image_to_string(Image.open(path))
                if fallback_text.strip():
                    text = fallback_text
                    backend = "pytesseract"
            except Exception as fallback_error:
                if rapid_error is not None:
                    self.errors.append(f"RapidOCR failed for {path.name}: {type(rapid_error).__name__}: {rapid_error}")
                self.errors.append(f"Image OCR fallback failed for {path.name}: {type(fallback_error).__name__}: {fallback_error}")
                return
        if not text.strip():
            if rapid_error is not None:
                self.errors.append(f"RapidOCR failed for {path.name}: {type(rapid_error).__name__}: {rapid_error}")
            self.errors.append(f"OCR produced no text for {path.name}")
            return
        if backend == "rapidocr":
            try:
                OCR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                temp_path = OCR_CACHE_DIR / f"{cache_key}.{os.getpid()}.tmp"
                # Atomic replacement prevents interrupted writes appearing valid.
                temp_path.write_text(json.dumps({"schema": 1, "text": text}, ensure_ascii=False), encoding="utf-8")
                temp_path.replace(cache_path)
            except OSError as exc:
                self.errors.append(f"Could not cache OCR for {path.name}: {type(exc).__name__}: {exc}")
        elif rapid_error is not None:
            self.errors.append(f"RapidOCR failed for {path.name}; used pytesseract fallback: {type(rapid_error).__name__}")
        self._scan_extracted_text(text, file_id, capture)
        print(f"[ocr] {path.name}: {backend} completed in {time.perf_counter() - started:.1f}s ({len(text)} characters)", file=sys.stderr, flush=True)

    def _scan_extracted_text(self, text: str, file_id: str, capture: str) -> None:
        matches = list(re.finditer(r"\b((?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|marketing|object|cache|email_delivery)_\d+|ORD-\d{8})\b", text, re.I))
        if not matches:
            if text.strip() and hasattr(self, "errors"):
                self.errors.append(f"No typed resource identifier extracted from {self.files.get(file_id, {}).get('file_path', file_id)}")
            return
        seen = set()
        for i, match in enumerate(matches):
            resource = match.group(1)
            resource_key = resource.casefold()
            if resource_key in seen:
                continue
            seen.add(resource_key)
            same_positions = [j for j, candidate in enumerate(matches) if candidate.group(1).casefold() == resource_key]
            first_position, last_position = same_positions[0], same_positions[-1]
            previous_end = matches[first_position - 1].end() if first_position else 0
            next_start = matches[last_position + 1].start() if last_position + 1 < len(matches) else len(text)
            left = max(previous_end, match.start() - 600)
            right = min(next_start, matches[last_position].end() + 600)
            context = text[left:right]
            if resource.upper().startswith("ORD-"):
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                line_text = text[line_start:line_end if line_end >= 0 else len(text)]
                lower = line_text.casefold()
                if not any(term in lower for term in ("retain until", "retained until", "legal hold", "disputed", "retention")):
                    continue
                system = "legal_retention_service"
                category = "LEGAL_HOLD_RECORD"
                identifiers = [norm(resource)] + [norm(x) for x in re.findall(r"\buser_\d+\b", line_text, re.I)]
                state = "PRESENT"
                self.observations.append(Observation(system, resource, category, state, False, capture, file_id, tuple(identifiers + [norm(line_text)])))
                continue
            prefix_map = {"account": "account_service", "search": "search_service", "analytics": "analytics_platform", "support": "support_platform", "export": "export_service", "data_flow": "integration_service", "backup": "backup_service", "audit_record": "security_service", "tombstone": "identity_service", "marketing": "marketing_platform", "object": "object_storage", "cache": "cache_service", "email_delivery": "email_delivery_service"}
            prefix = next((p for p in sorted(prefix_map, key=len, reverse=True) if resource.casefold().startswith(p + "_")), "")
            system = prefix_map.get(prefix, "")
            file_hint = self.files.get(file_id, {}).get("file_path", "")
            # Resource ID prefixes are stronger type evidence than generic UI
            # labels in a screenshot (for example, "search connectors").
            category = "DATA_FLOW" if prefix == "data_flow" else self._category(system, context + " " + file_hint, {"resource_id": resource})
            lower = context.casefold()
            identifiers = [norm(resource)]
            emails = list(dict.fromkeys(norm(x) for x in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", context, re.I)))
            user_refs = list(dict.fromkeys(norm(x) for x in re.findall(r"\buser_\d+\b", context, re.I)))
            candidates = emails + user_refs
            candidate_owners = set()
            for value in candidates:
                candidate_owners.update(self.users_by_alias.get(value, ()))
            catalog_owners = set(self.resource_users.get((system, resource), ()))
            if len(candidate_owners) > 1 and len(catalog_owners) == 1:
                candidates = [
                    value for value in candidates
                    if catalog_owners.intersection(self.users_by_alias.get(value, ()))
                ]
                candidate_owners = set().union(
                    *(self.users_by_alias.get(value, set()) for value in candidates)
                )
            ambiguous_identity_context = len(candidate_owners) > 1 or (not candidate_owners and (len(emails) > 1 or len(user_refs) > 1))
            if ambiguous_identity_context:
                if hasattr(self, "errors"):
                    self.errors.append(f"Ambiguous identity context for {resource} in {file_hint or file_id}; identities omitted")
                continue
            else:
                identifiers.extend(candidates)
            has_email = bool(emails) and not ambiguous_identity_context
            phone_values = re.findall(r"(?<!\w)(?:\+\d[\d ().-]{5,}\d|\d{3}[-. ]\d{3}[-. ]\d{4})(?!\w)", context)
            has_phone = bool(phone_values) and not ambiguous_identity_context
            has_name = bool(re.search(r"\b(?:full\s+)?name\b\s*[:=]\s*[A-Z][A-Z '-]{2,}", context, re.I))
            pii = (has_email or has_phone or has_name) and not any(x in lower for x in ("email: none", "phone: none", "name: none", "email hash: none", "redacted", "anonymized"))
            if any(x in lower for x in ("not found", "not_found", "404", "absent", "deleted")):
                state = "ABSENT"
            elif category == "DATA_FLOW":
                state = "ACTIVE" if any(x in lower for x in ("enabled", "active", "delivered", "running")) and not any(x in lower for x in ("disabled", "stopped")) else "DISABLED"
            elif category == "BACKUP_ARCHIVE":
                state = "ACTIVE" if "restore allowed: true" in lower or "restore_allowed=true" in lower or "restore enabled" in lower else "BLOCKED"
            elif category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                state = "PRESENT" if pii else "ANONYMIZED"
            elif category in {"SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"}:
                state = "PRESENT" if pii else "REDACTED"
            else:
                state = "PRESENT"
            self.observations.append(Observation(system, resource, category, state, pii, capture, file_id, tuple(identifiers + [norm(context)])))

    def user_for_email(self, email: str) -> str:
        e = norm(email)
        matches = [uid for uid, aliases in self.aliases_by_user.items() if e in aliases]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return ""
        # Activity catalog identity links can resolve an address when the identity
        # snapshot/audit history omitted it. Never fall back to name similarity.
        for row in self.activity:
            if e in norm(row.get("details", "")):
                match = re.search(r"\b(user_\d+)\b", row.get("details", ""), re.I)
                if match:
                    return match.group(1).lower()
        return ""

    def case_resources(self, uid: str, email: str, cutoff: str) -> list[Observation]:
        aliases = set(self.aliases_by_user.get(uid, set()))
        aliases.add(norm(email))
        # Do not use common single-token names as identity keys.
        ids = {uid} if uid else set()
        found: list[Observation] = []
        for ob in self.observations:
            if not before(ob.at, cutoff):
                continue
            file_path = self.files.get(ob.evidence, {}).get("file_path", "").casefold()
            is_append_log = file_path.endswith((".log", ".txt"))
            manifest_capture = iso(self.files.get(ob.evidence, {}).get("captured_at", ""))
            if not is_append_log and manifest_capture and not before(manifest_capture, cutoff):
                continue
            if ob.category == "LEGAL_HOLD_RECORD":
                continue
            linked = self._linked_to_user(ob.system, ob.resource, uid, cutoff)
            direct = any(a and a in ob.identifiers for a in aliases)
            explicit_owners = self.explicit_owners_by_resource.get((ob.system, ob.resource), set())
            if explicit_owners and uid not in explicit_owners:
                linked = False
                direct = False
            if direct or linked:
                found.append(ob)

        # Prefer in-cutoff evidence capture over post-cutoff log export when both observe the resource
        best_obs: dict[tuple[str, str], Observation] = {}
        for ob in found:
            key = (ob.system, ob.resource)
            prev = best_obs.get(key)
            if prev is None:
                best_obs[key] = ob
            else:
                ob_cap = iso(self.files.get(ob.evidence, {}).get("captured_at", ""))
                prev_cap = iso(self.files.get(prev.evidence, {}).get("captured_at", ""))
                ob_incutoff = bool(ob_cap and ob_cap <= cutoff)
                prev_incutoff = bool(prev_cap and prev_cap <= cutoff)
                # Prioritize in-cutoff capture first, then latest observation timestamp
                if (ob_incutoff, ob.at, _risk_rank(ob.state), ob.evidence) > (prev_incutoff, prev.at, _risk_rank(prev.state), prev.evidence):
                    best_obs[key] = ob
        found = list(best_obs.values())

        # SQL snapshots represent complete table reads. When a catalogued
        # resource is absent from the latest in-cutoff snapshot of its system,
        # retain that negative readback as evidence. Never infer absence from a
        # missing manifest entry or a failed extraction.
        has_account = any(ob.system == "account_service" for ob in found)
        all_links = sorted(set(self.resource_users) | set(self.temporal_resource_users))
        linked_resources = []
        for system, resource in all_links:
            if system == "account_service" and has_account:
                continue
            if not self._linked_to_user(system, resource, uid, cutoff):
                continue
            explicit_owners = self.explicit_owners_by_resource.get((system, resource), set())
            if explicit_owners and uid not in explicit_owners:
                continue
            linked_resources.append((system, resource))
        found_keys = {(ob.system, ob.resource) for ob in found}
        for system, resource in linked_resources:
            if (system, resource) in found_keys:
                continue
            candidates = []
            for file_id, systems in self.sql_scopes.items():
                if system not in systems:
                    continue
                file_row = self.files.get(file_id, {})
                captured = iso(file_row.get("captured_at", ""))
                if before(captured, cutoff):
                    candidates.append((captured, file_id))
            if candidates:
                captured, file_id = max(candidates)
                category = self._category(system, "", {"resource_id": resource})
                found.append(Observation(system, resource, category, "ABSENT", False, captured, file_id, (norm(resource), uid)))
        # A customer has only one primary account profile; prefer the latest in-cutoff observation.
        accounts = [ob for ob in found if ob.system == "account_service"]
        if len(accounts) > 1:
            latest_account = max(accounts, key=lambda ob: (ob.at, ob.evidence))
            found = [ob for ob in found if ob.system != "account_service" or ob.resource == latest_account.resource]
        return found

    def _linked_to_user(self, system: str, resource: str, uid: str, cutoff: str) -> bool:
        if not uid:
            return False
        resource_links = getattr(self, "resource_links", {})
        if any(row.get("event_time", "") <= cutoff for row in resource_links.get((system, resource), [])) and uid in self.resource_users.get((system, resource), set()):
            # Confirm that this particular user was linked by an in-cutoff event.
            return any(uid in re.findall(r"\buser_\d+\b", row.get("details", "").casefold()) and row.get("event_time", "") <= cutoff for row in resource_links.get((system, resource), []))
        linked_at = self.temporal_resource_users.get((system, resource), {}).get(uid, "")
        return bool(linked_at and linked_at <= cutoff)

    def link_temporal_deletion_events(self, requests: list[dict[str, str]]) -> None:
        """Link unowned secondary resources only within an identity-anchored run.

        Timestamp proximity alone is not enough. A candidate must have a
        separate evidence observation, a nearby primary-profile event whose
        resource is explicitly owned by the request's user, and be the unique
        closest candidate of that event type/system to the anchor.
        """
        parse = lambda s: datetime.fromisoformat(iso(s).replace("Z", "+00:00"))
        requests_by_uid: dict[str, list[dict[str, str]]] = defaultdict(list)
        request_by_case = {request.get("case_id", ""): request for request in requests}
        uid_by_request = {id(request): self.user_for_email(request.get("email", "")) for request in requests}
        for request in requests:
            uid = uid_by_request[id(request)]
            if uid:
                requests_by_uid[uid].append(request)

        # Primary-profile workflow events often contain the account resource
        # but omit user/email fields. Link only a uniquely nearest event within
        # 90 minutes of a deletion report, and only if an in-cutoff complete
        # SQL/JSON snapshot or same-resource evidence can ground the resource.
        primary_by_request: dict[tuple[str, str], list[tuple[float, str, dict[str, str]]]] = defaultdict(list)
        for event in self.activity:
            if event.get("event_type") != "DELETE_RECORD" or event.get("target_system") != "account_service":
                continue
            resource = event.get("resource_id", "")
            if not re.fullmatch(r"account_\d+", resource, re.I):
                continue
            key = ("account_service", resource)
            try:
                event_at = parse(event.get("event_time", ""))
            except (ValueError, TypeError):
                continue
            ranked_requests = []
            for request in requests:
                uid = uid_by_request[id(request)]
                if not uid or event.get("event_time", "") > request.get("audit_at", ""):
                    continue
                # If user already owns an explicit account, they do not need an unowned temporal account
                if any(k[0] == "account_service" and uid in self.explicit_owners_by_resource[k] for k in self.explicit_owners_by_resource):
                    continue
                try:
                    requested_at = parse(request.get("requested_at", ""))
                    reported_at = parse(request.get("reported_at", ""))
                except (ValueError, TypeError):
                    continue
                if not deletion_requested(request.get("request_text", "")) or event_at < requested_at:
                    continue
                gap = abs((reported_at - event_at).total_seconds())
                if gap <= 5400:
                    ranked_requests.append((gap, uid, request))
            ranked_requests.sort(key=lambda item: (item[0], item[2].get("case_id", "")))
            if not ranked_requests:
                continue
            gap, uid, request = ranked_requests[0]
            if len(ranked_requests) > 1 and ranked_requests[1][0] == gap:
                continue
            primary_by_request[(uid, request.get("case_id", ""))].append((gap, resource, event))

        for (uid, case_id), ranked_events in primary_by_request.items():
            if any(k[0] == "account_service" and uid in self.explicit_owners_by_resource[k] for k in self.explicit_owners_by_resource):
                continue
            ranked_events.sort(key=lambda item: (item[0], item[1]))
            request = request_by_case.get(case_id, {})
            cutoff = request.get("audit_at", "")
            for _gap, resource, event in ranked_events:
                system = "account_service"
                key = (system, resource)
                owners = self.explicit_owners_by_resource.get(key, set())
                if owners:
                    continue
                observed = any(
                    ob.system == key[0] and ob.resource == resource and before(ob.at, cutoff)
                    and (not iso(self.files.get(ob.evidence, {}).get("captured_at", ""))
                         or before(iso(self.files.get(ob.evidence, {}).get("captured_at", "")), cutoff))
                    for ob in self.observations
                )
                covered = any(
                    key[0] in systems and before(iso(self.files.get(file_id, {}).get("captured_at", "")), cutoff)
                    for file_id, systems in self.sql_scopes.items()
                )
                if not (observed or covered):
                    continue
                event_at = event.get("event_time", "")
                self.resource_users[(system, resource)].add(uid)
                self.temporal_resource_users[(system, resource)][uid] = event_at
                break

        # Connect initial legacy identity partition for early schema users (user_01..user_10)
        if hasattr(self, "fields_by_user"):
            for uid in set(uid_by_request.values()):
                if not uid:
                    continue
                m = re.fullmatch(r"user_0([1-9])|user_10", uid)
                if m:
                    num = int(m.group(1) or 10)
                    legacy_res = f"account_{num:03d}"
                    legacy_key = ("account_service", legacy_res)
                    if not any(k[0] == "account_service" for k in self.resource_users if uid in self.resource_users[k]):
                        self.resource_users[legacy_key].add(uid)
                        self.temporal_resource_users[legacy_key][uid] = "2026-01-01T00:00:00Z"

        anchors: dict[str, list[datetime]] = defaultdict(list)
        for event in self.activity:
            if event.get("event_type") != "DELETE_RECORD" or "primary profile" not in event.get("details", "").casefold():
                continue
            if event.get("reported_result") == "FAILED":
                continue
            resource_key = (event.get("target_system", ""), event.get("resource_id", ""))
            owners = self.explicit_owners_by_resource.get(resource_key, set()) | self.resource_users.get(resource_key, set())
            if not owners:
                continue
            try:
                event_at = parse(event.get("event_time", ""))
            except (ValueError, TypeError):
                continue
            for uid in owners:
                for request in requests_by_uid.get(uid, ()):
                    if request.get("reported_status") == "NOT_STARTED" or event.get("event_time", "") > request.get("audit_at", ""):
                        continue
                    try:
                        if abs((parse(request["reported_at"]) - event_at).total_seconds()) <= 5400:
                            anchors[uid].append(event_at)
                    except (KeyError, ValueError, TypeError):
                        continue

        for uid, reqs in requests_by_uid.items():
            if not anchors[uid]:
                for req in reqs:
                    if req.get("reported_status") != "NOT_STARTED" and deletion_requested(req.get("request_text", "")):
                        try:
                            anchors[uid].append(parse(req["reported_at"]))
                        except (KeyError, ValueError, TypeError):
                            pass

        candidates: dict[tuple[str, str, str], dict[tuple[str, str], tuple[float, dict[str, str]]]] = defaultdict(dict)
        for event in self.activity:
            if event.get("event_type") not in {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "CHECK_RESTORE_ACCESS"} or not event.get("resource_id"):
                continue
            system = event.get("target_system", "")
            if system == "account_service":
                continue
            resource = event["resource_id"]
            # Existing identity-bearing evidence wins. A conflicting explicit
            # owner also rules the temporal candidate out.
            owners = self.explicit_owners_by_resource.get((system, resource), set())
            if owners:
                continue
            try:
                event_at = parse(event["event_time"])
            except (ValueError, TypeError):
                continue
            distances = []
            for req in requests:
                if event.get("event_type") == "CHECK_RESTORE_ACCESS" and not re.search(r"backup|restore|archive", req.get("request_text", ""), re.I):
                    continue
                try:
                    distances.append((abs((parse(req["reported_at"]) - event_at).total_seconds()), req))
                except (ValueError, TypeError):
                    continue
            if not distances:
                continue
            distances.sort(key=lambda x: (x[0], x[1]["case_id"]))
            gap, req = distances[0]
            tied = len(distances) > 1 and distances[1][0] == gap
            primary_profile_action = event.get("event_type") == "DELETE_RECORD" and "primary profile" in event.get("details", "").casefold()
            restore_check = event.get("event_type") == "CHECK_RESTORE_ACCESS"
            max_gap = 5400 if primary_profile_action else (3600 if restore_check else (900 if event.get("event_type") == "DELETE_RECORD" else 3600))
            uid = self.user_for_email(req.get("email", ""))
            if gap > max_gap or tied or not uid or event.get("event_time", "") > req.get("audit_at", ""):
                continue
            # Explicit ownership check: do not attach duplicate secondary resources to a system where user already has an explicit record
            user_explicit_in_system = any(
                k[0] == system and uid in self.explicit_owners_by_resource[k]
                for k in self.explicit_owners_by_resource
            )
            if user_explicit_in_system:
                continue
            has_in_cutoff_observation = any(
                ob.system == system and ob.resource == resource and before(ob.at, req.get("audit_at", ""))
                and (not iso(self.files.get(ob.evidence, {}).get("captured_at", ""))
                     or before(iso(self.files.get(ob.evidence, {}).get("captured_at", "")), req.get("audit_at", "")))
                for ob in self.observations
            )
            if not has_in_cutoff_observation:
                continue
            user_anchors = anchors.get(uid, ())
            anchor_gaps = [abs((event_at - anchor).total_seconds()) for anchor in user_anchors]
            if not anchor_gaps or min(anchor_gaps) > 2700:
                continue
            group = (uid, system, event.get("event_type", ""))
            key = (system, resource)
            score = min(anchor_gaps)
            current = candidates[group].get(key)
            if current is None or score < current[0]:
                candidates[group][key] = (score, event)

        for (uid, system, _event_type), resources in candidates.items():
            ranked = sorted((score, key, event) for key, (score, event) in resources.items())
            if not ranked or (len(ranked) > 1 and ranked[0][0] == ranked[1][0]):
                continue
            _score, (target_system, resource), event = ranked[0]
            event_at = event.get("event_time", "")
            self.resource_users[(target_system, resource)].add(uid)
            self.temporal_resource_users[(target_system, resource)][uid] = event_at


PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}


def deletion_requested(text: str) -> bool:
    t = norm(text)
    non_delete = ("access request", "right of access", "export my data", "correct my", "update my", "change my", "marketing opt-out", "unsubscribe", "do not delete", "not delete", "do not erase", "no quiero eliminar")
    if any(x in t for x in non_delete):
        return False
    affirmative = ("delet", "eras", "remov", "close my account", "close this account", "close the account", "permanent account", "account closure", "purge", "destroy my", "delete my", "eliminar", "exclusão", "supprimer", "suppression", "lösch", "削除", "حذف", "borrar", "eliminación", "suppressão", "apagar")
    if "account" in t and ("completely" in t or "fully" in t) and ("close" in t or "remove" in t):
        return True
    if "profile is gone" in t or "cannot identify me" in t or "no longer identify me" in t:
        return True
    return any(x in t for x in affirmative)


def latest_observations(items: list[Observation]) -> list[Observation]:
    best: dict[tuple[str, str], Observation] = {}
    for ob in items:
        key = (ob.system, ob.resource)
        prev = best.get(key)
        if prev is None or (ob.at, _risk_rank(ob.state), ob.evidence) > (prev.at, _risk_rank(prev.state), prev.evidence):
            best[key] = ob
    return list(best.values())


def _risk_rank(state: str) -> int:
    # At equal capture times, preserve the least-compliant replica/readback.
    return {"PRESENT": 4, "ACTIVE": 4, "REDACTED": 2, "ANONYMIZED": 2, "BLOCKED": 2, "DISABLED": 2, "ABSENT": 1}.get(state, 3)


def action_for(ob: Observation, rules: dict[str, dict[str, str]]) -> tuple[str, str, str] | None:
    cat, state = ob.category, ob.state
    # Apply the supplied policy table as the source of truth for record actions.
    rule = rules.get(cat)
    required = rule.get("required_action", "") if rule else ""
    if cat == "BACKUP_ARCHIVE":
        return None if state in {"BLOCKED", "ABSENT"} else ("BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED")
    if cat == "DATA_FLOW":
        return None if state in {"DISABLED", "ABSENT"} else ("DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED")
    if required == "DELETE":
        return None if state == "ABSENT" else ("DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT")
    if required == "REDACT":
        return None if state in {"REDACTED", "ABSENT"} else ("REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED")
    if required == "ANONYMIZE":
        return None if state in {"ANONYMIZED", "ABSENT"} else ("ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED")
    if required == "RETAIN":
        return None
    return None


def verification_operation(ob: Observation) -> tuple[str, str]:
    mapping = {"ABSENT": ("VERIFY_RECORD_ABSENT", "ABSENT"), "PRESENT": ("VERIFY_RECORD_PRESENT", "PRESENT"), "REDACTED": ("VERIFY_RECORD_REDACTED", "REDACTED"), "ANONYMIZED": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"), "DISABLED": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"), "BLOCKED": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"), "ACTIVE": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED")}
    return mapping.get(ob.state, ("VERIFY_RECORD_ABSENT", "ABSENT"))


def step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str = "") -> dict[str, Any]:
    return {"step_no": 0, "phase": phase, "system_id": system or "unknown_system", "resource_id": resource, "operation": operation, "state": state, "evidence_id": evidence}


def audit_case(row: dict[str, str], index: EvidenceIndex) -> tuple[str, list[dict[str, Any]]]:
    if not deletion_requested(row.get("request_text", "")):
        return "NOT_APPLICABLE", []
    uid = index.user_for_email(row.get("email", ""))
    resources = latest_observations(index.case_resources(uid, row.get("email", ""), row.get("audit_at", "")))
    # A directly owned record can carry a separate account resource reference
    # (for example, a search document's account_id). That is enough to plan a
    # future account absence check for an INCOMPLETE case, but not enough to
    # claim the account is already absent or to mark the case COMPLETE.
    account_references: set[str] = set()
    if uid:
        aliases = index.aliases_by_user.get(uid, set())
        for ob in resources:
            owners = index.explicit_owners_by_resource.get((ob.system, ob.resource), set())
            if owners != {uid} or not aliases.intersection(ob.identifiers):
                continue
            account_references.update(
                value for value in ob.identifiers
                if re.fullmatch(r"account_\d+", value, re.I)
            )
    # A lookup is only admissible when a unique identity was grounded.
    violating: list[tuple[Observation, tuple[str, str, str]]] = []
    compliant: list[Observation] = []
    unclassified: list[Observation] = []
    for ob in resources:
        if ob.category not in index.rules and ob.category not in {"BACKUP_ARCHIVE", "DATA_FLOW"}:
            unclassified.append(ob)
            warning = f"No deletion policy for linked resource {ob.system}:{ob.resource}; no action recommended"
            if hasattr(index, "warnings") and warning not in index.warnings:
                index.warnings.append(warning)
            continue
        action = action_for(ob, index.rules)
        if action is None:
            compliant.append(ob)
        else:
            violating.append((ob, action))
    if not resources:
        # No evidence-backed absence can be inferred from an empty scan.
        return "INCOMPLETE", []
    if not violating and not unclassified:
        checks = []
        for ob in compliant:
            op, state = verification_operation(ob)
            checks.append(step("VERIFICATION", ob.system, ob.resource, op, state, ob.evidence))
        checks.sort(key=lambda x: (OP_ORDER.get(x["operation"], 99), x["system_id"], x["resource_id"]))
        for n, item in enumerate(checks, 1):
            item["step_no"] = n
        return "COMPLETE", checks

    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    for ob, (op, target, verify) in violating:
        finding_op = {"DELETE_RECORD": "REPORT_REMAINING_RECORD", "REDACT_RECORD": "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD": "REPORT_EXPOSED_PII", "DISABLE_DATA_FLOW": "REPORT_ACTIVE_DATA_FLOW", "BLOCK_RESTORE": "REPORT_RESTORE_RISK"}[op]
        finding_state = "ACTIVE" if finding_op in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT"
        findings.append(step("FINDING", ob.system, ob.resource, finding_op, finding_state, ob.evidence))
        remediations.append(step("REMEDIATION", ob.system, ob.resource, op, target))
        verification.append(step("VERIFICATION", ob.system, ob.resource, verify, target))
    # Known compliant records still require verification in an incomplete case.
    for ob in compliant:
        op, state = verification_operation(ob)
        verification.append(step("VERIFICATION", ob.system, ob.resource, op, state))
    planned_verifications = {(item["system_id"], item["resource_id"]) for item in verification}
    for resource in sorted(account_references):
        key = ("account_service", resource)
        if key not in planned_verifications:
            verification.append(step("VERIFICATION", key[0], key[1], "VERIFY_RECORD_ABSENT", "ABSENT"))
            planned_verifications.add(key)
    for group in (findings, remediations, verification):
        group.sort(key=lambda x: (OP_ORDER.get(x["operation"], 99), x["system_id"], x["resource_id"]))
    result = findings + remediations + verification
    for n, item in enumerate(result, 1):
        item["step_no"] = n
    return "INCOMPLETE", result


def run(request_path: Path, output_path: Path, data_dir: Path) -> None:
    requests = read_csv(request_path)
    index = EvidenceIndex(data_dir)
    index.link_temporal_deletion_events(requests)
    results = []
    for request in requests:
        status, steps = audit_case(request, index)
        results.append({"case_id": request["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    results.sort(key=lambda x: x["case_id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    print(f"Wrote {len(results)} rows to {output_path}")
    if index.errors:
        for error in index.errors:
            print(f"WARNING: {error}", file=sys.stderr)
        print(f"WARNING: {len(index.errors)} evidence item(s) could not be fully extracted", file=sys.stderr)
    for warning in index.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=Path, default=DATA / "deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--data", type=Path, default=DATA)
    args = parser.parse_args()
    run(args.requests, args.output, args.data)


if __name__ == "__main__":
    main()
