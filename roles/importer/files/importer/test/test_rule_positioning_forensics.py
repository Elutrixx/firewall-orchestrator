import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT_PATH = (
    Path(__file__).parents[4]
    / "middleware"
    / "files"
    / "FWO.Middleware.Server"
    / "Diagnostics"
    / "rule_positioning_forensics.py"
)
FIXTURE_PATH = Path(__file__).parent / "data" / "rule_positioning_forensics"


def load_collector() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rule_positioning_forensics", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = load_collector()


def test_discover_and_load_attempts_are_scoped_to_requested_task(tmp_path: Path) -> None:
    wanted = tmp_path / "impltask-42" / "attempt-20260101"
    unwanted = tmp_path / "impltask-43" / "attempt-20260102"
    wanted.mkdir(parents=True)
    unwanted.mkdir(parents=True)
    event = {
        "sequence": 1,
        "implementationTaskId": 42,
        "timestampUtc": "2026-01-01T00:00:00Z",
        "eventName": "manifest",
    }
    (wanted / "events.jsonl").write_text(json.dumps(event) + "\nnot-json\n", encoding="utf-8")
    (unwanted / "events.jsonl").write_text("{}\n", encoding="utf-8")

    paths = collector.discover_attempts(tmp_path, 42)
    attempt = collector.load_attempt(paths[0])

    assert paths == [wanted]
    assert [item["implementationTaskId"] for item in attempt.events] == [42]
    assert attempt.sha256
    assert attempt.errors == ["line 2: JSONDecodeError"]


def test_source_truth_summary_indexes_all_rulebases_links_and_exact_section_name() -> None:
    database_value = database_fixture()
    database_value["latestConfig"]["config"]["gateways"].append(
        {
            "Uid": "other-gateway-uid",
            "Name": "Other gateway",
            "RulebaseLinks": [
                {
                    "from_rulebase_uid": "layer-uid",
                    "from_rule_uid": None,
                    "to_rulebase_uid": "section-uid",
                    "link_type": "section",
                    "is_initial": False,
                    "is_global": False,
                    "is_section": True,
                }
            ],
        }
    )

    summary = collector.source_truth_summary(database_value)

    assert summary["available"] is True
    assert summary["importId"] == 700
    assert summary["rulebaseCount"] == 2
    assert summary["gatewayCount"] == 2
    assert summary["allRulebaseLinks"][1]["is_section"] is True
    section = summary["sectionLinkedRulebases"][0]
    assert section["targetRulebaseExists"] is True
    assert section["targetName"]["raw"] == "[SOURCE]\u00a0< [DESTINATION]"
    assert section["targetName"]["unicodeCodePoints"][8] == 160
    assert section["targetName"]["utf8Bytes"][8:10] == [194, 160]
    assert len(summary["targetGatewaySectionLinkedRulebases"]) == 1
    assert summary["targetGatewaySectionLinkedRulebases"][0]["link"]["gatewayUid"] == "gateway-uid"
    assert len(summary["otherGatewaySectionLinkedRulebases"]) == 1


def test_build_report_contains_every_source_in_one_document(tmp_path: Path) -> None:
    attempt_directory = tmp_path / "impltask-42" / "attempt-one"
    attempt_directory.mkdir(parents=True)
    events = [
        {
            "sequence": 1,
            "implementationTaskId": 42,
            "timestampUtc": "2026-01-01T00:00:00Z",
            "eventName": "graph-interpreter-result",
            "payload": {"success": True},
        },
        {
            "sequence": 2,
            "implementationTaskId": 42,
            "timestampUtc": "2026-01-01T00:00:01Z",
            "eventName": "complete",
            "payload": {"status": "COMPLETE"},
        },
    ]
    raw_text = "".join(json.dumps(event) + "\n" for event in events)
    (attempt_directory / "events.jsonl").write_text(raw_text, encoding="utf-8")
    attempt = collector.load_attempt(attempt_directory)
    database = collector.CommandResult(["psql"], 0, json.dumps(database_fixture()), "")
    journal = collector.CommandResult(["journalctl"], 0, "middleware line\n", "")
    systemd = collector.CommandResult(["systemctl"], 0, "ActiveState=active\n", "")

    report = collector.build_report(42, [attempt], database, journal, systemd)

    assert "===== BEGIN 01 MANIFEST AND CORRELATION IDENTITIES =====" in report
    assert "===== BEGIN 03 NORMALIZED LATEST_CONFIG EVIDENCE =====" in report
    assert "===== BEGIN 05 GRAPHQL AND SNAPSHOT EVIDENCE =====" in report
    assert "===== BEGIN 10 AUTOMATIC CONCLUSION =====" in report
    assert "===== BEGIN 12 TIMINGS CHECKSUMS AND RAW ARTIFACTS =====" in report
    assert "[SOURCE]\u00a0< [DESTINATION]" in report
    assert "middleware line" in report
    assert raw_text.splitlines()[0] in report
    assert raw_text.splitlines()[1] in report


def test_output_directory_builds_one_unique_report_name(tmp_path: Path) -> None:
    arguments = collector.parse_arguments(["42", "--output-dir", str(tmp_path)])

    output = collector.default_output_path(arguments.implementation_task_id, arguments.output_dir)

    assert output.parent == tmp_path
    assert output.name.startswith("rule-positioning-forensics-impltask-42-")
    assert output.suffix == ".txt"


def test_database_query_is_scoped_and_does_not_read_credentials() -> None:
    query = collector.database_query(42)

    assert "WHERE i.id = 42" in query
    assert "latest_config" in query
    assert "import_control" in query
    assert "request.implelement" in query
    assert "credential" not in query


def test_realistic_fixture_report_has_all_handoffs_and_finds_deliberate_loss(tmp_path: Path) -> None:
    attempt_directory = tmp_path / "impltask-42" / "attempt-fixture"
    attempt_directory.mkdir(parents=True)
    fixture_events = (FIXTURE_PATH / "events.jsonl").read_text(encoding="utf-8")
    (attempt_directory / "events.jsonl").write_text(fixture_events, encoding="utf-8")
    database_value = json.loads((FIXTURE_PATH / "database.json").read_text(encoding="utf-8"))
    database = collector.CommandResult(["psql"], 0, json.dumps(database_value), "", 0.25)
    journal = collector.CommandResult(["journalctl"], 0, "fixture journal", "", 0.5)
    systemd = collector.CommandResult(["systemctl"], 0, "ActiveState=active", "", 0.1)

    report = collector.build_report(
        42,
        [collector.load_attempt(attempt_directory)],
        database,
        journal,
        systemd,
        database,
    )

    for section_number in range(1, 13):
        marker = f"===== BEGIN {section_number:02d} "
        assert marker in report
        assert f"===== END {section_number:02d} " in report
    assert '"status": "COMPLETE"' in report
    assert '"latestConfigImportMatchesPositioning": true' in report
    assert '"code": "SELECTOR_COMPARISON_FAILED"' in report
    assert '"sectionUid": "section-target"' in report
    assert '"sectionUid": "section-similar"' in report
    assert '"sha256":' in report
    assert '"database": 0.25' in report
    assert "RAW JSONL ATTEMPT 1" in report


def test_completeness_rejects_latest_config_from_another_positioning_import(tmp_path: Path) -> None:
    attempt_directory = tmp_path / "impltask-42" / "attempt-drift"
    attempt_directory.mkdir(parents=True)
    events = [
        {
            "eventName": "import-selected",
            "payload": {"importId": 701},
        },
        {
            "eventName": "complete",
            "payload": {"status": "COMPLETE"},
        },
    ]
    (attempt_directory / "events.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    database_value = database_fixture()
    database = collector.CommandResult(["psql"], 0, json.dumps(database_value), "")
    successful_command = collector.CommandResult(["read-only"], 0, "", "")

    report = collector.build_report(
        42,
        [collector.load_attempt(attempt_directory)],
        database,
        successful_command,
        successful_command,
        database,
    )

    assert '"status": "INCOMPLETE"' in report
    assert '"latestConfigImportMatchesPositioning": false' in report
    assert "positioning selected imports [701], latest_config is 700" in report


def test_write_report_refuses_overwrite_and_uses_owner_only_mode(tmp_path: Path) -> None:
    output = tmp_path / "report.txt"

    collector.write_report(output, "evidence")

    assert output.read_text(encoding="utf-8") == "evidence"
    if stat.S_IMODE(output.stat().st_mode) != 0o600:
        pytest.skip("filesystem does not expose Unix owner-only mode")
    with pytest.raises(FileExistsError):
        collector.write_report(output, "replacement")


def database_fixture() -> dict[str, Any]:
    return {
        "implementationTask": {"id": 42, "device_id": 20, "rule_position": None},
        "implementationElements": [],
        "requestTask": {"id": 30, "ticket_id": 10},
        "ticket": {"id": 10},
        "gateway": {"id": 20, "uid": "gateway-uid", "name": "Gateway"},
        "management": {"id": 50, "uid": "management-uid", "name": "Management"},
        "latestImportControl": {"control_id": 700, "successful_import": True},
        "latestConfig": {
            "managementId": 50,
            "importId": 700,
            "config": {
                "rulebases": [
                    {
                        "uid": "layer-uid",
                        "name": "Layer",
                        "mgm_uid": "management-uid",
                        "rules": {"guard-rule": {"uid": "guard-rule"}},
                    },
                    {
                        "uid": "section-uid",
                        "name": "[SOURCE]\u00a0< [DESTINATION]",
                        "mgm_uid": "management-uid",
                        "rules": {},
                    },
                ],
                "gateways": [
                    {
                        "Uid": "gateway-uid",
                        "Name": "Gateway",
                        "RulebaseLinks": [
                            {
                                "from_rulebase_uid": None,
                                "from_rule_uid": None,
                                "to_rulebase_uid": "layer-uid",
                                "link_type": "ordered",
                                "is_initial": True,
                                "is_global": False,
                                "is_section": False,
                            },
                            {
                                "from_rulebase_uid": "layer-uid",
                                "from_rule_uid": None,
                                "to_rulebase_uid": "section-uid",
                                "link_type": "section",
                                "is_initial": False,
                                "is_global": False,
                                "is_section": True,
                            },
                        ],
                    }
                ],
            },
        },
    }
