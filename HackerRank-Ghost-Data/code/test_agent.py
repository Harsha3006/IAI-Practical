"""Small deterministic regression suite for policy and output logic."""
import csv
import contextlib
import io
import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

import main


RULES = {
    "USER_PROFILE": {"required_action": "DELETE"},
    "ANALYTICS_PROFILE": {"required_action": "ANONYMIZE"},
    "SUPPORT_MESSAGE": {"required_action": "REDACT"},
    "BACKUP_ARCHIVE": {"required_action": "RETAIN"},
}


class AgentPolicyTests(unittest.TestCase):
    def test_non_deletion_requests_are_not_applicable(self):
        self.assertFalse(main.deletion_requested("Please export my data and correct my phone number."))
        self.assertFalse(main.deletion_requested("Unsubscribe me from marketing emails."))

    def test_multilingual_and_verification_requests_authorize_deletion(self):
        self.assertTrue(main.deletion_requested("Je demande la suppression définitive du compte."))
        self.assertTrue(main.deletion_requested("このアカウントの完全な削除を依頼します。"))
        self.assertTrue(main.deletion_requested("Confirm the profile is gone and records cannot identify me."))

    def test_custom_active_flow_blocks_completion(self):
        flow = main.Observation("integration_service", "data_flow_7", "DATA_FLOW", "ACTIVE", False, "2026-09-01T00:00:00Z", "evidence_1")
        self.assertEqual(main.action_for(flow, RULES), ("DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED"))

    def test_custom_anonymized_analytics_satisfies_policy(self):
        record = main.Observation("analytics_platform", "analytics_7", "ANALYTICS_PROFILE", "ANONYMIZED", False, "2026-09-01T00:00:00Z", "evidence_1")
        self.assertIsNone(main.action_for(record, RULES))

    def test_custom_shared_support_with_pii_requires_redaction(self):
        record = main.Observation("support_platform", "support_7", "SUPPORT_MESSAGE", "PRESENT", True, "2026-09-01T00:00:00Z", "evidence_1")
        self.assertEqual(main.action_for(record, RULES), ("REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"))

    def test_backup_is_retained_but_restore_blocked(self):
        active = main.Observation("backup_service", "backup_7", "BACKUP_ARCHIVE", "ACTIVE", False, "2026-09-01T00:00:00Z", "evidence_1")
        blocked = main.Observation("backup_service", "backup_7", "BACKUP_ARCHIVE", "BLOCKED", False, "2026-09-01T00:00:00Z", "evidence_1")
        self.assertEqual(main.action_for(active, RULES)[0], "BLOCK_RESTORE")
        self.assertIsNone(main.action_for(blocked, RULES))

    def test_absent_backups_and_data_flows_are_not_remediated(self):
        backup = main.Observation("backup_service", "backup_8", "BACKUP_ARCHIVE", "ABSENT", False, "2026-09-01T00:00:00Z", "evidence_1")
        flow = main.Observation("integration_service", "data_flow_8", "DATA_FLOW", "ABSENT", False, "2026-09-01T00:00:00Z", "evidence_1")
        self.assertIsNone(main.action_for(backup, RULES))
        self.assertIsNone(main.action_for(flow, RULES))

    def test_retain_policy_never_recommends_deletion(self):
        retained = main.Observation("legal_retention_service", "order_8", "LEGAL_HOLD_RECORD", "ABSENT", False, "2026-09-01T00:00:00Z", "evidence_1")
        rules = {**RULES, "LEGAL_HOLD_RECORD": {"required_action": "RETAIN"}}
        self.assertIsNone(main.action_for(retained, rules))

    def test_unknown_category_stays_incomplete_without_destructive_steps(self):
        unknown = main.Observation("object_storage", "object_8", "UNKNOWN", "PRESENT", False, "2026-09-01T00:00:00Z", "evidence_1")
        index = SimpleNamespace(
            user_for_email=lambda email: "user_1",
            case_resources=lambda uid, email, cutoff: [unknown],
            rules=RULES,
            aliases_by_user={"user_1": set()},
            explicit_owners_by_resource={},
            warnings=[],
        )
        status, steps = main.audit_case(
            {"email": "one@example.com", "request_text": "Delete my account", "audit_at": "2026-09-02T00:00:00Z"},
            index,
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps, [])
        self.assertTrue(index.warnings)

    def test_account_and_security_evidence_receive_required_verifications(self):
        account = main.Observation(
            "account_service", "account_8", "USER_PROFILE", "ABSENT", False,
            "2026-09-01T00:00:00Z", "evidence_account", ("account_8", "one@example.com"),
        )
        audit = main.Observation(
            "security_service", "audit_record_8", "SECURITY_AUDIT_LOG", "PRESENT", False,
            "2026-09-01T00:00:00Z", "evidence_audit", ("audit_record_8", "one@example.com"),
        )
        index = SimpleNamespace(
            user_for_email=lambda email: "user_1",
            case_resources=lambda uid, email, cutoff: [account, audit],
            rules={**RULES, "SECURITY_AUDIT_LOG": {"required_action": "RETAIN"}},
            aliases_by_user={"user_1": {"one@example.com"}},
            explicit_owners_by_resource={("account_service", "account_8"): {"user_1"}},
        )
        status, steps = main.audit_case(
            {"email": "one@example.com", "request_text": "Delete my account", "audit_at": "2026-09-02T00:00:00Z"},
            index,
        )
        self.assertEqual(status, "COMPLETE")
        self.assertEqual(
            [(item["resource_id"], item["operation"], item["evidence_id"]) for item in steps],
            [
                ("account_8", "VERIFY_RECORD_ABSENT", "evidence_account"),
                ("audit_record_8", "VERIFY_RECORD_PRESENT", "evidence_audit"),
            ],
        )

    def test_latest_snapshot_prefers_least_compliant_same_time_replica(self):
        absent = main.Observation("account_service", "account_8", "USER_PROFILE", "ABSENT", False, "2026-09-01T00:00:00Z", "evidence_1")
        present = main.Observation("account_service", "account_8", "USER_PROFILE", "PRESENT", True, "2026-09-01T00:00:00Z", "evidence_1")
        self.assertEqual(main.latest_observations([absent, present])[0].state, "PRESENT")

    def test_temporal_link_cannot_override_another_users_explicit_resource_owner(self):
        resource = ("support_platform", "support_7")
        index = SimpleNamespace(
            aliases_by_user={"user_1": {"user_1"}}, observations=[],
            files={"snapshot": {"captured_at": "2026-09-01T00:00:00Z"}},
            explicit_owners_by_resource={resource: {"user_2"}},
            resource_users={}, resource_links={},
            temporal_resource_users={resource: {"user_1": "2026-08-31T00:00:00Z"}},
            sql_scopes={"snapshot": {"support_platform"}},
        )
        index._linked_to_user = lambda system, resource_id, uid, cutoff: True
        found = main.EvidenceIndex.case_resources(index, "user_1", "one@example.com", "2026-09-02T00:00:00Z")
        self.assertEqual(found, [])

    def test_temporal_secondary_link_requires_primary_anchor_and_selects_unique_candidate(self):
        events = [
            {"event_type": "DELETE_RECORD", "target_system": "account_service", "resource_id": "account_1", "event_time": "2026-09-01T09:00:00Z", "details": "submitted primary profile"},
            {"event_type": "ANONYMIZE_RECORD", "target_system": "analytics_platform", "resource_id": "analytics_1", "event_time": "2026-09-01T09:20:00Z", "details": "completed"},
            {"event_type": "ANONYMIZE_RECORD", "target_system": "analytics_platform", "resource_id": "analytics_2", "event_time": "2026-09-01T09:21:00Z", "details": "completed"},
        ]
        index = SimpleNamespace(
            activity=events,
            explicit_owners_by_resource={("account_service", "account_1"): {"user_1"}},
            observations=[
                main.Observation("analytics_platform", "analytics_1", "ANALYTICS_PROFILE", "ANONYMIZED", False, "2026-09-01T09:20:00Z", "evidence_1"),
                main.Observation("analytics_platform", "analytics_2", "ANALYTICS_PROFILE", "ANONYMIZED", False, "2026-09-01T09:21:00Z", "evidence_1"),
            ],
            files={"evidence_1": {"captured_at": "2026-09-01T09:30:00Z"}},
            resource_users=defaultdict(set), temporal_resource_users=defaultdict(dict),
        )
        index.user_for_email = lambda email: "user_1"
        request = {"case_id": "case_x", "email": "one@example.com", "reported_at": "2026-09-01T10:00:00Z", "audit_at": "2026-09-01T12:00:00Z", "request_text": "Delete my account"}
        main.EvidenceIndex.link_temporal_deletion_events(index, [request])
        self.assertEqual(index.temporal_resource_users, {("analytics_platform", "analytics_1"): {"user_1": "2026-09-01T09:20:00Z"}})

    def test_unique_primary_workflow_event_links_to_absence_snapshot(self):
        event = {"event_type": "DELETE_RECORD", "target_system": "account_service", "resource_id": "account_71", "event_time": "2026-09-01T09:59:00Z", "details": "Deletion worker completed profile request."}
        request = {"case_id": "case_a", "email": "one@example.com", "requested_at": "2026-08-31T00:00:00Z", "reported_at": "2026-09-01T10:00:00Z", "audit_at": "2026-09-03T00:00:00Z", "request_text": "Delete my account"}
        index = SimpleNamespace(
            activity=[event], explicit_owners_by_resource={}, observations=[],
            files={"snapshot": {"captured_at": "2026-09-02T00:00:00Z"}},
            sql_scopes={"snapshot": {"account_service"}},
            resource_users=defaultdict(set), temporal_resource_users=defaultdict(dict),
            resource_links=defaultdict(list),
        )
        index.user_for_email = lambda email: "user_1"
        main.EvidenceIndex.link_temporal_deletion_events(index, [request])
        self.assertEqual(index.temporal_resource_users[("account_service", "account_71")]["user_1"], event["event_time"])

        evidence_index = object.__new__(main.EvidenceIndex)
        evidence_index.aliases_by_user = {"user_1": {"user_1", "one@example.com"}}
        evidence_index.observations = []
        evidence_index.files = index.files
        evidence_index.explicit_owners_by_resource = {}
        evidence_index.resource_users = index.resource_users
        evidence_index.resource_links = index.resource_links
        evidence_index.temporal_resource_users = index.temporal_resource_users
        evidence_index.sql_scopes = index.sql_scopes
        resources = evidence_index.case_resources("user_1", "one@example.com", request["audit_at"])
        self.assertEqual([(o.resource, o.state, o.evidence) for o in resources], [("account_71", "ABSENT", "snapshot")])

    def test_primary_workflow_event_cannot_override_explicit_owner(self):
        event = {"event_type": "DELETE_RECORD", "target_system": "account_service", "resource_id": "account_72", "event_time": "2026-09-01T09:59:00Z", "details": "Deletion worker completed profile request."}
        request = {"case_id": "case_a", "email": "one@example.com", "requested_at": "2026-08-31T00:00:00Z", "reported_at": "2026-09-01T10:00:00Z", "audit_at": "2026-09-03T00:00:00Z", "request_text": "Delete my account"}
        index = SimpleNamespace(
            activity=[event], explicit_owners_by_resource={("account_service", "account_72"): {"user_2"}}, observations=[],
            files={"snapshot": {"captured_at": "2026-09-02T00:00:00Z"}},
            sql_scopes={"snapshot": {"account_service"}},
            resource_users=defaultdict(set), temporal_resource_users=defaultdict(dict),
            resource_links=defaultdict(list),
        )
        index.user_for_email = lambda email: "user_1"
        main.EvidenceIndex.link_temporal_deletion_events(index, [request])
        self.assertEqual(dict(index.temporal_resource_users), {})

    def test_closer_explicit_account_event_blocks_a_second_temporal_candidate(self):
        events = [
            {"event_type": "DELETE_RECORD", "target_system": "account_service", "resource_id": "account_owned", "event_time": "2026-09-01T09:59:00Z", "details": "submitted primary profile"},
            {"event_type": "DELETE_RECORD", "target_system": "account_service", "resource_id": "account_unowned", "event_time": "2026-09-01T09:55:00Z", "details": "Deletion worker completed profile request."},
        ]
        request = {"case_id": "case_a", "email": "one@example.com", "requested_at": "2026-08-31T00:00:00Z", "reported_at": "2026-09-01T10:00:00Z", "audit_at": "2026-09-03T00:00:00Z", "request_text": "Delete my account"}
        index = SimpleNamespace(
            activity=events, explicit_owners_by_resource={("account_service", "account_owned"): {"user_1"}},
            observations=[], files={"snapshot": {"captured_at": "2026-09-02T00:00:00Z"}},
            sql_scopes={"snapshot": {"account_service"}},
            resource_users=defaultdict(set), temporal_resource_users=defaultdict(dict), resource_links=defaultdict(list),
        )
        index.user_for_email = lambda email: "user_1"
        main.EvidenceIndex.link_temporal_deletion_events(index, [request])
        self.assertEqual(dict(index.temporal_resource_users), {})

    def test_legal_order_rows_keep_their_own_identity_and_nonretained_orders_are_ignored(self):
        index = SimpleNamespace(observations=[])
        text = (
            "ORD-20260001 | user_8 | Card dispute | Retain until 2033-05-04\n"
            "ORD-20260002 | user_12 | Tax correction | Retain until 2033-05-09\n"
            "Invoice order ORD-20260003 | user_17 | paid and delivered"
        )
        main.EvidenceIndex._scan_extracted_text(index, text, "evidence_test", "2026-05-29T00:00:00Z")
        self.assertEqual([o.resource for o in index.observations], ["ORD-20260001", "ORD-20260002"])
        self.assertIn("user_8", index.observations[0].identifiers)
        self.assertNotIn("user_12", index.observations[0].identifiers)
        self.assertIn("user_12", index.observations[1].identifiers)
        self.assertNotIn("user_8", index.observations[1].identifiers)

    def test_deleted_status_does_not_hide_identifiers_still_in_profile(self):
        state, has_pii = main.EvidenceIndex._state(
            "account_service", "USER_PROFILE",
            {"resource_id": "account_2", "email": "nobody@example.com", "account_status": "DELETED"},
        )
        self.assertEqual((state, has_pii), ("PRESENT", True))

    def test_shared_support_message_detects_identifiers_inside_message_text(self):
        state, has_pii = main.EvidenceIndex._state(
            "support_platform", "SUPPORT_MESSAGE",
            {"message_text": "Please reply to nobody@example.com about the order."},
        )
        self.assertEqual((state, has_pii), ("PRESENT", True))

    def test_generic_replica_sql_records_are_extracted_and_classified(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset = self._mini_dataset(Path(temp))
            sql_path = dataset / "evidence" / "records" / "composite_snapshot.sql"
            record = '{"resource_id":"account_2","user_id":"user_1","email":"nobody@example.com","account_status":"DELETED"}'
            sql_path.write_text(
                "CREATE TABLE customer_data_primary (resource_id TEXT, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);\n"
                f"INSERT INTO customer_data_primary VALUES ('account_2','account_service','customer_profiles','{record}','2026-01-01T00:00:00Z');\n",
                encoding="utf-8",
            )
            with (dataset / "evidence_files.csv").open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["file_id", "file_path", "origin", "captured_at"])
                writer.writerow(["evidence_sql", "evidence/records/composite_snapshot.sql", "test", "2026-01-01T00:00:00Z"])
            index = main.EvidenceIndex(dataset)
            observations = [o for o in index.observations if o.resource == "account_2"]
            self.assertEqual(len(observations), 1)
            self.assertEqual((observations[0].system, observations[0].category), ("account_service", "USER_PROFILE"))
            self.assertEqual((observations[0].state, observations[0].has_pii), ("PRESENT", True))
            self.assertIn("account_service", index.sql_scopes["evidence_sql"])

    def test_json_service_logs_link_resource_to_identity_on_same_trace(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "events.log"
            log.write_text(
                '2026-09-16T08:57:31Z {"service":"account_service","trace_id":"trace-a","event":"profile_lookup_started","lookup_key":"person@example.com"}\n'
                '2026-09-16T08:57:34Z {"service":"account_service","trace_id":"trace-a","resource_id":"account_3960","event":"profile_lookup_completed","rows":"0","http_status":"404"}\n',
                encoding="utf-8",
            )
            index = object.__new__(main.EvidenceIndex)
            index.observations, index.files = [], {}
            main.EvidenceIndex._scan_text(index, log, "evidence_test", "2026-09-18T00:00:00Z")
        self.assertEqual(len(index.observations), 1)
        observation = index.observations[0]
        self.assertEqual((observation.system, observation.resource, observation.state), ("account_service", "account_3960", "ABSENT"))
        self.assertIn("person@example.com", observation.identifiers)

    def test_typed_handover_preserves_active_data_flow_state(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "handover.txt"
            log.write_text(
                "2026-10-01T12:00:00Z | integration_service | data_flow_7 | DATA_FLOW | ACTIVE | person@example.com\n",
                encoding="utf-8",
            )
            index = object.__new__(main.EvidenceIndex)
            index.observations, index.files = [], {}
            main.EvidenceIndex._scan_text(index, log, "evidence_test", "2026-10-01T12:00:00Z")
        self.assertEqual(index.observations[0].state, "ACTIVE")
        self.assertEqual(main.action_for(index.observations[0], RULES)[0], "DISABLE_DATA_FLOW")

    def test_repeated_ocr_resource_markers_do_not_steal_neighbor_identity(self):
        text = (
            "data_flow_1121 connector customer_analytics_warehouse jain.aditi@gmail.com continuous active\n"
            "data_flow_9846 connector customer_analytics_warehouse lucia-torres@gmail.com continuous active\n"
            "selected connector data_flow_1121 owner jain.aditi@gmail.com\n"
        )
        index = object.__new__(main.EvidenceIndex)
        index.observations = []
        index.errors = []
        index.files = {
            "image": {"file_path": "evidence/images/connector_management_console.png"},
            "trace": {"file_path": "evidence/logs/connector_trace.log"},
        }
        index.users_by_alias = {"jain.aditi@gmail.com": {"user_14"}, "lucia-torres@gmail.com": {"user_15"}}
        index.resource_users = {("integration_service", "data_flow_1121"): {"user_14"}}
        main.EvidenceIndex._scan_extracted_text(index, text, "image", "2026-08-07T08:00:00Z")
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "connector_trace.log"
            log.write_text(
                "2026-08-22T11:58:08Z level=DEBUG service=integration_service trace_id=flow-trace event=connector_config_read_started subject_key=lucia-torres@gmail.com\n"
                "2026-08-22T11:58:11Z level=WARN service=integration_service trace_id=flow-trace resource_id=data_flow_9846 event=connector_heartbeat enabled=true scheduler_registered=true last_run=success\n",
                encoding="utf-8",
            )
            main.EvidenceIndex._scan_text(index, log, "trace", "2026-08-22T12:00:00Z")
        index.resource_users = defaultdict(set, index.resource_users)
        main.EvidenceIndex._build_resource_owner_index(index)

        flow_1121 = [o for o in index.observations if o.resource == "data_flow_1121"]
        flow_9846 = [o for o in index.observations if o.resource == "data_flow_9846"]
        self.assertTrue(flow_1121)
        self.assertTrue(all(o.category == "DATA_FLOW" and o.state == "ACTIVE" for o in flow_1121 + flow_9846))
        self.assertEqual(index.explicit_owners_by_resource[("integration_service", "data_flow_1121")], {"user_14"})
        self.assertEqual(index.explicit_owners_by_resource[("integration_service", "data_flow_9846")], {"user_15"})
        flow_1121_ids = set().union(*(set(o.identifiers) for o in flow_1121))
        self.assertIn("jain.aditi@gmail.com", flow_1121_ids)
        self.assertNotIn("lucia-torres@gmail.com", flow_1121_ids)

    def test_ambiguous_ocr_does_not_create_an_observation(self):
        index = object.__new__(main.EvidenceIndex)
        index.observations = []
        index.errors = []
        index.files = {"image": {"file_path": "evidence/images/analytics_console.png"}}
        index.users_by_alias = {
            "one@example.com": {"user_1"},
            "two@example.com": {"user_2"},
        }
        index.resource_users = {}
        main.EvidenceIndex._scan_extracted_text(
            index,
            "analytics_8 email one@example.com email two@example.com anonymized",
            "image",
            "2026-09-01T00:00:00Z",
        )
        self.assertEqual(index.observations, [])
        self.assertTrue(any("Ambiguous identity context" in error for error in index.errors))

    def _mini_dataset(self, root: Path, malformed: bool = False) -> Path:
        dataset = root / "dataset"
        (dataset / "evidence" / "records").mkdir(parents=True)
        def write_csv(name, header, rows):
            with (dataset / name).open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                writer.writerows(rows)
        write_csv("deletion_requests.csv", ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"], [["case,quoted", "nobody@example.com", "2026-01-01T00:00:00Z", "NOT_STARTED", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "Delete my account"]])
        write_csv("user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"], [["user_1", "N Example", "nobody@example.com", "", "", "2025-01-01T00:00:00Z"]])
        write_csv("user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], [])
        write_csv("system_activity.csv", ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"], [])
        write_csv("deletion_rules.csv", ["rule_id", "data_category", "condition", "required_action"], [["r1", "USER_PROFILE", "Always", "DELETE"]])
        manifest = [["evidence_bad", "evidence/records/bad.json", "test", "2026-01-01T00:00:00Z"]] if malformed else []
        write_csv("evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], manifest)
        if malformed:
            (dataset / "evidence" / "records" / "bad.json").write_text("{broken", encoding="utf-8")
        return dataset

    def test_csv_escaping_and_json_output_for_unresolved_case(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dataset = self._mini_dataset(root)
            output = root / "output.csv"
            with contextlib.redirect_stderr(io.StringIO()):
                main.run(dataset / "deletion_requests.csv", output, dataset)
            with output.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["case_id"], "case,quoted")
            self.assertEqual(json.loads(rows[0]["steps_json"]), [])
            self.assertEqual(rows[0]["deletion_status"], "INCOMPLETE")

    def test_malformed_evidence_is_reported_without_corrupting_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dataset = self._mini_dataset(root, malformed=True)
            index = main.EvidenceIndex(dataset)
            self.assertTrue(any("JSONDecodeError" in error for error in index.errors))
            output = root / "output.csv"
            with contextlib.redirect_stderr(io.StringIO()):
                main.run(dataset / "deletion_requests.csv", output, dataset)
            with output.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["deletion_status"], "INCOMPLETE")

    def test_contact_lookup_log_yields_secondary_identifier_delete(self):
        index = object.__new__(main.EvidenceIndex)
        index.observations = []
        index.errors = []
        index.files = {}
        index.resource_users = defaultdict(set)
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "contact_lookup.log"
            log.write_text(
                "2026-08-20T10:00:00Z level=INFO service=contact_service event=contact_lookup_completed resource_id=contact_123 identifier_value=user@example.com rows=1\n",
                encoding="utf-8",
            )
            main.EvidenceIndex._scan_text(index, log, "file_contact", "2026-08-20T10:00:00Z")
        self.assertEqual(len(index.observations), 1)
        ob = index.observations[0]
        self.assertEqual(ob.category, "SECONDARY_IDENTIFIER")
        self.assertEqual(ob.state, "PRESENT")
        action = main.action_for(ob, {**RULES, "SECONDARY_IDENTIFIER": {"required_action": "DELETE"}})
        self.assertEqual(action, ("DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT"))

    def test_message_pii_scan_log_yields_support_message_redact(self):
        index = object.__new__(main.EvidenceIndex)
        index.observations = []
        index.errors = []
        index.files = {}
        index.resource_users = defaultdict(set)
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "support_scan.log"
            log.write_text(
                "2026-08-20T10:00:00Z level=INFO service=support_platform event=message_pii_scan resource_id=msg_456 pii_detected=true user_id=user_88\n",
                encoding="utf-8",
            )
            main.EvidenceIndex._scan_text(index, log, "file_msg", "2026-08-20T10:00:00Z")
        self.assertEqual(len(index.observations), 1)
        ob = index.observations[0]
        self.assertEqual(ob.category, "SUPPORT_MESSAGE")
        self.assertEqual(ob.state, "PRESENT")
        action = main.action_for(ob, RULES)
        self.assertEqual(action, ("REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"))

    def test_append_log_vs_snapshot_cutoff_filtering(self):
        index = object.__new__(main.EvidenceIndex)
        index.user_for_email = lambda email: "user_1"
        index.aliases_by_user = {"user_1": {"user@example.com"}}
        index.resource_users = {
            ("account_service", "acc_1"): {"user_1"},
            ("search_service", "doc_1"): {"user_1"},
        }
        index.temporal_resource_users = defaultdict(dict)
        index.files = {
            "ev_log": {"file_path": "logs/audit.log", "captured_at": "2026-09-10T00:00:00Z"},
            "ev_snapshot": {"file_path": "dumps/snapshot.sql", "captured_at": "2026-09-10T00:00:00Z"},
        }
        cutoff = "2026-09-05T00:00:00Z"
        ob_log = main.Observation("search_service", "doc_1", "SEARCH_INDEX_ENTRY", "ABSENT", False, "2026-09-01T00:00:00Z", "ev_log", ("user@example.com",))
        ob_snap = main.Observation("account_service", "acc_1", "USER_PROFILE", "ABSENT", False, "2026-09-01T00:00:00Z", "ev_snapshot", ("user@example.com",))
        index.observations = [ob_log, ob_snap]
        index.sql_scopes = {}
        index.explicit_owners_by_resource = {}

        resources = main.EvidenceIndex.case_resources(index, "user_1", "user@example.com", cutoff)
        res_names = [o.resource for o in resources]
        self.assertIn("doc_1", res_names)
        self.assertNotIn("acc_1", res_names)

    def test_primary_account_prefers_latest_observation(self):
        index = object.__new__(main.EvidenceIndex)
        index.user_for_email = lambda email: "user_1"
        index.aliases_by_user = {"user_1": {"user@example.com"}}
        index.resource_users = {
            ("account_service", "account_old"): {"user_1"},
            ("account_service", "account_new"): {"user_1"},
        }
        index.temporal_resource_users = defaultdict(dict)
        index.files = {
            "ev_1": {"file_path": "logs/old.log", "captured_at": "2026-01-01T00:00:00Z"},
            "ev_2": {"file_path": "logs/new.log", "captured_at": "2026-08-01T00:00:00Z"},
        }
        cutoff = "2026-09-01T00:00:00Z"
        ob_old = main.Observation("account_service", "account_old", "USER_PROFILE", "PRESENT", False, "2026-01-01T00:00:00Z", "ev_1", ("user@example.com",))
        ob_new = main.Observation("account_service", "account_new", "USER_PROFILE", "ABSENT", False, "2026-08-01T00:00:00Z", "ev_2", ("user@example.com",))
        index.observations = [ob_old, ob_new]
        index.sql_scopes = {}
        index.explicit_owners_by_resource = {}

        resources = main.EvidenceIndex.case_resources(index, "user_1", "user@example.com", cutoff)
        acc_resources = [o for o in resources if o.system == "account_service"]
        self.assertEqual(len(acc_resources), 1)
        self.assertEqual(acc_resources[0].resource, "account_new")

    def test_in_cutoff_capture_preferred_over_post_cutoff_log_for_same_resource(self):
        index = object.__new__(main.EvidenceIndex)
        index.user_for_email = lambda email: "user_test"
        index.aliases_by_user = {"user_test": {"test@example.com"}}
        index.resource_users = {}
        index.temporal_resource_users = defaultdict(dict)
        index.files = {
            "ev_incutoff": {"file_path": "databases/inventory.sql", "captured_at": "2026-09-16T08:30:00Z"},
            "ev_postcutoff": {"file_path": "logs/future_export.log", "captured_at": "2026-09-18T12:00:00Z"},
        }
        cutoff = "2026-09-16T09:00:00Z"
        ob_incutoff = main.Observation("backup_service", "backup_test", "BACKUP_ARCHIVE", "ACTIVE", False, "2026-09-16T08:00:00Z", "ev_incutoff", ("test@example.com",))
        ob_postcutoff = main.Observation("backup_service", "backup_test", "BACKUP_ARCHIVE", "ACTIVE", False, "2026-09-16T08:50:00Z", "ev_postcutoff", ("test@example.com",))
        index.observations = [ob_incutoff, ob_postcutoff]
        index.sql_scopes = {}
        index.explicit_owners_by_resource = {}

        resources = main.EvidenceIndex.case_resources(index, "user_test", "test@example.com", cutoff)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].evidence, "ev_incutoff")

    def test_explicit_account_owner_blocks_unowned_temporal_account_attachment(self):
        index = object.__new__(main.EvidenceIndex)
        index.explicit_owners_by_resource = {("account_service", "account_explicit"): {"user_test"}}
        index.resource_users = defaultdict(set, {("account_service", "account_explicit"): {"user_test"}})
        index.temporal_resource_users = defaultdict(dict)
        index.sql_scopes = {}
        index.observations = []
        index.files = {}
        index.activity = [
            {
                "activity_id": "act_1",
                "event_time": "2026-08-19T10:50:00Z",
                "event_type": "DELETE_RECORD",
                "target_system": "account_service",
                "resource_id": "account_unowned",
                "details": "Deletion worker submitted primary profile account_unowned to account_service.",
            }
        ]
        requests = [
            {
                "case_id": "case_test",
                "email": "test@example.com",
                "requested_at": "2026-08-16T12:00:00Z",
                "reported_at": "2026-08-19T11:00:00Z",
                "audit_at": "2026-09-01T12:00:00Z",
                "request_text": "Please delete my account.",
            }
        ]
        index.user_for_email = lambda email: "user_test"
        main.EvidenceIndex.link_temporal_deletion_events(index, requests)
        self.assertNotIn("user_test", index.resource_users.get(("account_service", "account_unowned"), set()))

    def test_not_started_request_and_failed_primary_deletion_do_not_anchor(self):
        index = object.__new__(main.EvidenceIndex)
        index.explicit_owners_by_resource = {("account_service", "account_1"): {"user_test"}}
        index.resource_users = defaultdict(set, {("account_service", "account_1"): {"user_test"}})
        index.temporal_resource_users = defaultdict(dict)
        index.sql_scopes = {}
        index.observations = []
        index.files = {}
        index.activity = [
            {
                "activity_id": "act_failed",
                "event_time": "2026-09-07T08:00:00Z",
                "event_type": "DELETE_RECORD",
                "target_system": "account_service",
                "resource_id": "account_1",
                "reported_result": "FAILED",
                "details": "Deletion worker submitted primary profile account_1 to account_service.",
            },
            {
                "activity_id": "act_sec",
                "event_time": "2026-09-07T08:15:00Z",
                "event_type": "ANONYMIZE_RECORD",
                "target_system": "analytics_platform",
                "resource_id": "analytics_unowned",
                "details": "Policy action completed for analytics_unowned.",
            },
        ]
        requests = [
            {
                "case_id": "case_not_started",
                "email": "test@example.com",
                "requested_at": "2026-09-05T09:00:00Z",
                "reported_status": "NOT_STARTED",
                "reported_at": "2026-09-07T09:00:00Z",
                "audit_at": "2026-09-16T09:00:00Z",
                "request_text": "Please delete my account permanently.",
            }
        ]
        index.user_for_email = lambda email: "user_test"
        main.EvidenceIndex.link_temporal_deletion_events(index, requests)
        self.assertNotIn("user_test", index.resource_users.get(("analytics_platform", "analytics_unowned"), set()))



if __name__ == "__main__":
    unittest.main()
