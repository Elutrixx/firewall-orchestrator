#!/usr/bin/env python3
# ruff: noqa: S608, UP045
"""Collect one implementation task's temporary rule-positioning evidence into one report."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

DEFAULT_ARTIFACT_ROOT = Path("/usr/local/fworch/tmp/rule-positioning-forensics")
DEFAULT_OUTPUT_ROOT = Path(tempfile.gettempdir())
DEFAULT_DATABASE = "fworchdb"
DEFAULT_SERVICE = "fworch-middleware"
REPORT_VERSION = 1


@dataclass(frozen=True)
class CommandResult:
    """Result of one best-effort read-only host command."""

    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class ArtifactAttempt:
    """One captured positioning attempt and its parsed and raw events."""

    directory: Path
    event_file: Path
    sha256: str
    raw_text: str
    events: list[dict[str, Any]]
    errors: list[str]


def parse_arguments(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse the intentionally small standalone CLI."""
    parser = argparse.ArgumentParser(
        description="Gather all available rule-positioning evidence for one implementation task."
    )
    parser.add_argument("implementation_task_id", type=positive_integer)
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--output", type=Path)
    output_group.add_argument("--output-dir", type=Path)
    parser.add_argument("--artifact-root", type=Path, default=DEFAULT_ARTIFACT_ROOT)
    parser.add_argument("--database", default=DEFAULT_DATABASE)
    parser.add_argument("--service", default=DEFAULT_SERVICE)
    return parser.parse_args(arguments)


def positive_integer(value: str) -> int:
    """Accept only positive task identifiers."""
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("implementation task id must be positive")
    return parsed


def run_command(command: Sequence[str], timeout_seconds: int = 60) -> CommandResult:
    """Run one read-only command without a shell and retain failures as evidence."""
    command_list = list(command)
    started = time.monotonic()
    try:
        result = subprocess.run(  # noqa: S603 - argv is built internally and no shell is used.
            command_list,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return CommandResult(command_list, result.returncode, result.stdout, result.stderr, time.monotonic() - started)
    except (OSError, subprocess.SubprocessError) as exception:
        return CommandResult(command_list, 127, "", type(exception).__name__, time.monotonic() - started)


def discover_attempts(artifact_root: Path, implementation_task_id: int) -> list[Path]:
    """Return only attempt directories belonging to the requested task."""
    task_directory = artifact_root / f"impltask-{implementation_task_id}"
    if not task_directory.is_dir():
        return []
    return sorted(path for path in task_directory.glob("attempt-*") if path.is_dir())


def load_attempt(directory: Path) -> ArtifactAttempt:
    """Read one append-only JSONL artifact without rejecting partial evidence."""
    event_file = directory / "events.jsonl"
    errors: list[str] = []
    if not event_file.is_file():
        return ArtifactAttempt(directory, event_file, "", "", [], ["events.jsonl is missing"])
    try:
        raw_bytes = event_file.read_bytes()
    except OSError as exception:
        return ArtifactAttempt(directory, event_file, "", "", [], [type(exception).__name__])

    raw_text = raw_bytes.decode("utf-8", errors="replace")
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                events.append(parsed)
            else:
                errors.append(f"line {line_number}: JSON value is not an object")
        except json.JSONDecodeError as exception:
            errors.append(f"line {line_number}: {type(exception).__name__}")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return ArtifactAttempt(directory, event_file, digest, raw_text, events, errors)


def event_time_window(attempts: Iterable[ArtifactAttempt]) -> Optional[tuple[datetime, datetime]]:
    """Find a bounded journal window around all valid event timestamps."""
    timestamps: list[datetime] = []
    for attempt in attempts:
        for event in attempt.events:
            parsed = parse_timestamp(event.get("timestampUtc"))
            if parsed is not None:
                timestamps.append(parsed)
    if not timestamps:
        return None
    margin = timedelta(minutes=2)
    return min(timestamps) - margin, max(timestamps) + margin


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse the capture's ISO timestamp while tolerating malformed partial lines."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def database_command(database: str, implementation_task_id: int) -> list[str]:
    """Build a read-only query for task context and the importer's latest normalized output."""
    query = database_query(implementation_task_id)
    command = ["psql", "-X", "--no-psqlrc", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", database, "-c", query]
    if effective_user_id() == 0 and shutil.which("runuser"):
        return ["runuser", "-u", "postgres", "--", *command]
    return command


def database_query(implementation_task_id: int) -> str:
    """Return the scoped SQL; the integer was validated before interpolation."""
    return f"""  # noqa: S608 - the interpolated value is a validated positive integer.
WITH target AS (
    SELECT i.*, r.ticket_id, r.mgm_id AS request_mgm_id
    FROM request.impltask i
    LEFT JOIN request.reqtask r ON r.id = i.reqtask_id
    WHERE i.id = {implementation_task_id}
), resolved AS (
    SELECT target.*, COALESCE(target.mgm_id, d.mgm_id, target.request_mgm_id) AS resolved_mgm_id
    FROM target
    LEFT JOIN device d ON d.dev_id = target.device_id
)
SELECT jsonb_pretty(jsonb_build_object(
    'implementationTask', to_jsonb(i),
    'implementationElements', COALESCE((
        SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id)
        FROM request.implelement e WHERE e.implementation_task_id = i.id
    ), '[]'::jsonb),
    'requestTask', to_jsonb(r),
    'ticket', to_jsonb(t),
    'gateway', CASE WHEN d.dev_id IS NULL THEN NULL ELSE jsonb_build_object(
        'id', d.dev_id, 'uid', d.dev_uid, 'name', d.dev_name, 'managementId', d.mgm_id,
        'localRulebaseUid', d.local_rulebase_uid, 'localRulebaseName', d.local_rulebase_name,
        'globalRulebaseUid', d.global_rulebase_uid, 'globalRulebaseName', d.global_rulebase_name
    ) END,
    'management', CASE WHEN m.mgm_id IS NULL THEN NULL ELSE jsonb_build_object(
        'id', m.mgm_id, 'uid', m.mgm_uid, 'name', m.mgm_name,
        'rulebaseUid', m.rulebase_uid, 'rulebaseName', m.rulebase_name,
        'lastImportAttempt', m.last_import_attempt,
        'lastImportAttemptSuccessful', m.last_import_attempt_successful
    ) END,
    'latestImportControl', to_jsonb(ic),
    'historicalRulebases', COALESCE((
        SELECT jsonb_agg(to_jsonb(rb) ORDER BY rb.id)
        FROM firewall.rulebase rb WHERE rb.mgm_id = i.resolved_mgm_id
    ), '[]'::jsonb),
    'historicalRulebaseLinks', COALESCE((
        SELECT jsonb_agg(to_jsonb(rbl) ORDER BY rbl.id)
        FROM firewall.rulebase_link rbl WHERE rbl.gw_id = i.device_id
    ), '[]'::jsonb),
    'historicalRules', COALESCE((
        SELECT jsonb_agg(to_jsonb(ru) ORDER BY ru.rule_id)
        FROM firewall.rule ru
        JOIN firewall.rulebase rb ON rb.id = ru.rulebase_id
        WHERE rb.mgm_id = i.resolved_mgm_id
    ), '[]'::jsonb),
    'latestConfig', CASE WHEN lc.mgm_id IS NULL THEN NULL ELSE jsonb_build_object(
        'managementId', lc.mgm_id, 'importId', lc.import_id, 'config', lc.config
    ) END
))
FROM resolved i
LEFT JOIN request.reqtask r ON r.id = i.reqtask_id
LEFT JOIN request.ticket t ON t.id = i.ticket_id
LEFT JOIN device d ON d.dev_id = i.device_id
LEFT JOIN management m ON m.mgm_id = i.resolved_mgm_id
LEFT JOIN latest_config lc ON lc.mgm_id = i.resolved_mgm_id
LEFT JOIN import_control ic ON ic.control_id = lc.import_id;
""".strip()


def parse_database_json(result: CommandResult) -> tuple[Optional[dict[str, Any]], list[str]]:
    """Parse the single psql JSON value without hiding command failures."""
    errors: list[str] = []
    if result.return_code != 0:
        errors.append(f"psql returned {result.return_code}: {result.stderr.strip()}")
        return None, errors
    if not result.stdout.strip():
        return None, ["implementation task was not found or psql returned no rows"]
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exception:
        return None, [f"database JSON could not be parsed: {type(exception).__name__}"]
    if not isinstance(value, dict):
        return None, ["database result is not a JSON object"]
    return value, errors


def journal_command(service: str, window: Optional[tuple[datetime, datetime]], task_id: int) -> list[str]:
    """Build a bounded middleware journal query."""
    command = ["journalctl", "--unit", service, "--no-pager", "--output", "short-iso-precise"]
    if window is not None:
        start, end = window
        return [*command, "--since", start.isoformat(), "--until", end.isoformat()]
    pattern = f"Implementation task {task_id}|impltask-{task_id}|implementationTaskId.*{task_id}"
    return [*command, "--since", "24 hours ago", "--grep", pattern]


def systemd_command(service: str) -> list[str]:
    """Read non-secret deployment identity and service state."""
    properties = "Id,ActiveState,SubState,MainPID,ExecMainStartTimestamp,FragmentPath,WorkingDirectory"
    return ["systemctl", "show", service, f"--property={properties}"]


def string_projection(value: Any) -> dict[str, Any]:
    """Mirror the useful cross-runtime string evidence for importer source values."""
    text = value if isinstance(value, str) else ""
    return {
        "isNull": value is None,
        "raw": value,
        "pythonRepr": repr(value),
        "trimmed": text.strip() if isinstance(value, str) else None,
        "invariantUppercaseApproximation": text.upper() if isinstance(value, str) else None,
        "unicodeCodePoints": [ord(character) for character in text],
        "utf8Bytes": list(text.encode("utf-8")),
        "utf8Hex": text.encode("utf-8").hex(),
    }


def source_truth_summary(database_value: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Index every importer rulebase and every section link from latest_config."""
    latest_config = (database_value or {}).get("latestConfig")
    target_gateway = (database_value or {}).get("gateway")
    target_gateway_uid = target_gateway.get("uid") if isinstance(target_gateway, dict) else None
    config = latest_config.get("config") if isinstance(latest_config, dict) else None
    if not isinstance(config, dict):
        return {"available": False, "reason": "latest_config.config is absent or is not an object"}

    rulebases = config.get("rulebases")
    gateways = config.get("gateways")
    rulebase_list = rulebases if isinstance(rulebases, list) else []
    gateway_list = gateways if isinstance(gateways, list) else []
    indexed = {item.get("uid"): item for item in rulebase_list if isinstance(item, dict) and item.get("uid")}
    section_links: list[dict[str, Any]] = []
    all_links: list[dict[str, Any]] = []
    for gateway in gateway_list:
        if not isinstance(gateway, dict):
            continue
        links = gateway.get("RulebaseLinks")
        for link in links if isinstance(links, list) else []:
            if not isinstance(link, dict):
                continue
            gateway_uid = gateway.get("Uid")
            evidence = {
                "gatewayUid": gateway_uid,
                "gatewayName": gateway.get("Name"),
                "isTargetGateway": gateway_uid == target_gateway_uid,
                **link,
            }
            all_links.append(evidence)
            if link.get("is_section") is True:
                section_links.append(evidence)

    sections: list[dict[str, Any]] = []
    for link in section_links:
        uid = link.get("to_rulebase_uid")
        rulebase = indexed.get(uid)
        sections.append(
            {
                "link": link,
                "targetRulebaseExists": rulebase is not None,
                "targetUid": uid,
                "targetName": string_projection(rulebase.get("name") if rulebase else None),
                "ruleCount": rule_count(rulebase),
            }
        )
    target_sections = [section for section in sections if section["link"]["isTargetGateway"]]
    other_sections = [section for section in sections if not section["link"]["isTargetGateway"]]
    return {
        "available": True,
        "managementId": latest_config.get("managementId"),
        "importId": latest_config.get("importId"),
        "targetGatewayUid": target_gateway_uid,
        "rulebaseCount": len(rulebase_list),
        "gatewayCount": len(gateway_list),
        "allRulebases": [rulebase_summary(rulebase) for rulebase in rulebase_list if isinstance(rulebase, dict)],
        "allRulebaseLinks": all_links,
        "sectionLinkedRulebases": sections,
        "targetGatewaySectionLinkedRulebases": target_sections,
        "otherGatewaySectionLinkedRulebases": other_sections,
    }


def rule_count(rulebase: Optional[dict[str, Any]]) -> int:
    """Count either dictionary- or list-shaped normalized rules."""
    if not rulebase:
        return 0
    rules = rulebase.get("rules")
    return len(rules) if isinstance(rules, (dict, list)) else 0


def rulebase_summary(rulebase: dict[str, Any]) -> dict[str, Any]:
    """Keep every identity needed to reconcile a normalized rulebase."""
    return {
        "uid": rulebase.get("uid"),
        "name": string_projection(rulebase.get("name")),
        "managementUid": rulebase.get("mgm_uid"),
        "isGlobal": rulebase.get("is_global"),
        "ruleCount": rule_count(rulebase),
        "ruleUids": list(rulebase.get("rules", {}).keys()) if isinstance(rulebase.get("rules"), dict) else [],
    }


def selected_events(attempts: Iterable[ArtifactAttempt]) -> list[dict[str, Any]]:
    """Pull the most useful comparisons forward while retaining raw JSONL later."""
    useful_names = {
        "graph-interpreter-result",
        "graph-interpreter-rejection",
        "guard-candidate-evaluation",
        "guard-selection-summary",
        "template-rendered",
        "section-candidate-comparison",
        "section-selection-result",
        "block-result",
        "persistence-result",
        "complete",
    }
    return [event for attempt in attempts for event in attempt.events if event.get("eventName") in useful_names]


def json_text(value: Any) -> str:
    """Render deterministic UTF-8-safe JSON for the human-copyable report."""
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def report_section(title: str, body: str) -> str:
    """Render one unmistakable report section."""
    return f"===== BEGIN {title} =====\n{body.rstrip()}\n===== END {title} =====\n"


def build_report(
    implementation_task_id: int,
    attempts: list[ArtifactAttempt],
    database_result: CommandResult,
    journal_result: CommandResult,
    systemd_result: CommandResult,
    end_database_result: Optional[CommandResult] = None,
) -> str:
    """Assemble all handoff evidence without silently dropping failed sources."""
    database_value, database_errors = parse_database_json(database_result)
    end_database_value, end_database_errors = parse_database_json(end_database_result or database_result)
    attempts_list = list(attempts)
    completeness = completeness_result(
        attempts_list,
        database_value,
        database_errors,
        end_database_value,
        end_database_errors,
        journal_result,
        systemd_result,
    )
    metadata = {
        "reportVersion": REPORT_VERSION,
        "status": completeness["status"],
        "createdUtc": datetime.now(timezone.utc).isoformat(),
        "implementationTaskId": implementation_task_id,
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "attemptCount": len(attempts_list),
        "databaseErrors": database_errors,
        "warning": "Contains full normalized importer output and operational data; handle accordingly.",
    }
    source_summary = source_truth_summary(database_value)
    sections = [report_section("01 MANIFEST AND CORRELATION IDENTITIES", json_text(metadata))]
    sections.append(report_section("02 COMPLETENESS AND IMPORT DRIFT", json_text(completeness)))
    sections.append(
        report_section(
            "03 NORMALIZED LATEST_CONFIG EVIDENCE",
            json_text(
                {
                    "summary": source_summary,
                    "latestConfig": (database_value or {}).get("latestConfig"),
                }
            ),
        )
    )
    sections.append(report_section("04 HISTORICAL DATABASE EVIDENCE", json_text(historical_evidence(database_value))))
    sections.append(
        report_section(
            "05 GRAPHQL AND SNAPSHOT EVIDENCE",
            json_text(events_for_stages(attempts_list, {"graphql", "snapshot", "snapshot-cache"})),
        )
    )
    sections.append(
        report_section(
            "06 INTERPRETED GRAPH EVIDENCE", json_text(events_for_stages(attempts_list, {"graph-interpretation"}))
        )
    )
    sections.append(
        report_section(
            "07 POSITIONING INPUTS AND LAYERGUARD",
            json_text(
                events_for_stages(
                    attempts_list,
                    {
                        "workflow",
                        "network-input",
                        "zone-input",
                        "layer-guard-snapshot",
                        "layer-guard-selection",
                        "strategy",
                    },
                )
            ),
        )
    )
    sections.append(
        report_section(
            "08 SECTION COMPARISONS AND EXECUTION",
            json_text(
                events_for_stages(
                    attempts_list,
                    {"section-template", "section-selection", "recipe-execution", "persistence"},
                )
            ),
        )
    )
    sections.append(report_section("09 PER-SECTION LINEAGE", json_text(lineage_rows(source_summary, attempts_list))))
    sections.append(
        report_section(
            "10 AUTOMATIC CONCLUSION", json_text(automatic_conclusion(source_summary, attempts_list, completeness))
        )
    )
    sections.append(
        report_section(
            "11 COLLECTION ERRORS AND HOST EVIDENCE",
            json_text(
                {
                    "databaseStart": command_result_evidence(database_result),
                    "databaseEnd": command_result_evidence(end_database_result or database_result),
                    "journal": command_result_evidence(journal_result, include_output=True),
                    "systemd": command_result_evidence(systemd_result, include_output=True),
                }
            ),
        )
    )
    sections.append(
        report_section(
            "12 TIMINGS CHECKSUMS AND RAW ARTIFACTS",
            raw_artifact_evidence(attempts_list, database_result, journal_result, systemd_result),
        )
    )
    return "\n".join(sections)


def completeness_result(
    attempts: list[ArtifactAttempt],
    database_start: Optional[dict[str, Any]],
    database_start_errors: list[str],
    database_end: Optional[dict[str, Any]],
    database_end_errors: list[str],
    journal: CommandResult,
    systemd: CommandResult,
) -> dict[str, Any]:
    """Name every reason the report cannot make an end-to-end claim."""
    reasons = list(database_start_errors) + list(database_end_errors)
    if not attempts:
        reasons.append("no forensic attempt directory was found")
    for attempt in attempts:
        reasons.extend(f"{attempt.directory.name}: {error}" for error in attempt.errors)
        terminal = next((event for event in reversed(attempt.events) if event.get("eventName") == "complete"), None)
        status = nested_value(terminal, "payload", "status")
        if status != "COMPLETE":
            reasons.append(f"{attempt.directory.name}: terminal status is {status or 'missing'}")
    start_import = nested_value(database_start, "latestConfig", "importId")
    end_import = nested_value(database_end, "latestConfig", "importId")
    positioning_imports = sorted(
        {
            nested_value(event, "payload", "importId")
            for event in events_named(attempts, "import-selected")
            if nested_value(event, "payload", "importId") is not None
        }
    )
    if start_import is None:
        reasons.append("latest_config is unavailable")
    if start_import != end_import:
        reasons.append(f"import drift during collection: {start_import} -> {end_import}")
    if not positioning_imports:
        reasons.append("positioning selected-import evidence is unavailable")
    elif positioning_imports != [start_import]:
        reasons.append(f"positioning selected imports {positioning_imports}, latest_config is {start_import}")
    if journal.return_code != 0:
        reasons.append(f"journal collection returned {journal.return_code}")
    if systemd.return_code != 0:
        reasons.append(f"systemd collection returned {systemd.return_code}")
    return {
        "status": "COMPLETE" if not reasons else "INCOMPLETE",
        "reasons": reasons,
        "latestConfigImportIdAtStart": start_import,
        "latestConfigImportIdAtEnd": end_import,
        "positioningImportIds": positioning_imports,
        "latestConfigImportMatchesPositioning": positioning_imports == [start_import],
    }


def nested_value(value: Any, *keys: str) -> Any:
    """Read a shallow JSON path without assuming complete evidence."""
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def historical_evidence(database_value: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Separate database persistence from workflow/importer data."""
    value = database_value or {}
    return {
        "implementationTask": value.get("implementationTask"),
        "implementationElements": value.get("implementationElements"),
        "requestTask": value.get("requestTask"),
        "ticket": value.get("ticket"),
        "gateway": value.get("gateway"),
        "management": value.get("management"),
        "latestImportControl": value.get("latestImportControl"),
        "historicalRulebases": value.get("historicalRulebases"),
        "historicalRulebaseLinks": value.get("historicalRulebaseLinks"),
        "historicalRules": value.get("historicalRules"),
    }


def events_for_stages(attempts: Iterable[ArtifactAttempt], stages: set) -> list[dict[str, Any]]:
    """Preserve complete event envelopes for the requested handoff stages."""
    return [event for attempt in attempts for event in attempt.events if event.get("stage") in stages]


def lineage_rows(source_summary: dict[str, Any], attempts: list[ArtifactAttempt]) -> list[dict[str, Any]]:
    """Join importer section identities to snapshot/interpreter/matcher evidence by UID."""
    comparisons = events_named(attempts, "section-candidate-comparison")
    rows: list[dict[str, Any]] = []
    for section in source_summary.get("sectionLinkedRulebases", []):
        uid = section.get("targetUid")
        matches = [event for event in comparisons if nested_value(event, "payload", "candidateUid") == uid]
        rows.append(
            {
                "sectionUid": uid,
                "source": section,
                "seenBySectionMatcher": bool(matches),
                "matcherComparisons": matches,
            }
        )
    return rows


def automatic_conclusion(
    source_summary: dict[str, Any],
    attempts: list[ArtifactAttempt],
    completeness: dict[str, Any],
) -> dict[str, Any]:
    """Identify the earliest evidenced loss without trusting the production failure label."""
    if completeness.get("status") != "COMPLETE":
        return {"code": "EVIDENCE_INCOMPLETE", "detail": completeness.get("reasons")}
    all_sections = source_summary.get("sectionLinkedRulebases", [])
    sections = source_summary.get("targetGatewaySectionLinkedRulebases", [])
    if not sections:
        if all_sections:
            return {
                "code": "ABSENT_FROM_TARGET_GATEWAY_NORMALIZED_SECTION_GRAPH",
                "detail": {
                    "targetGatewayUid": source_summary.get("targetGatewayUid"),
                    "sectionsOnOtherGateways": source_summary.get("otherGatewaySectionLinkedRulebases", []),
                },
            }
        return {
            "code": "ABSENT_FROM_NORMALIZED_SECTION_GRAPH",
            "detail": "latest_config has no section-linked rulebase",
        }
    interpreter = events_named(attempts, "graph-interpreter-result")
    if any(nested_value(event, "payload", "success") is False for event in interpreter):
        return {
            "code": "GRAPH_INTERPRETATION_REJECTED",
            "detail": events_named(attempts, "graph-interpreter-rejection"),
        }
    comparisons = events_named(attempts, "section-candidate-comparison")
    source_uids = {section.get("targetUid") for section in sections}
    relevant = [event for event in comparisons if nested_value(event, "payload", "candidateUid") in source_uids]
    selected = [event for event in relevant if nested_value(event, "payload", "isInSelectedLayer")]
    if selected and not any(nested_value(event, "payload", "comparison", "ordinalEqual") for event in selected):
        return {"code": "SELECTOR_COMPARISON_FAILED", "detail": relevant}
    if relevant and not selected:
        return {"code": "SECTION_ATTACHED_TO_ANOTHER_LAYER", "detail": relevant}
    selection_results = events_named(attempts, "section-selection-result")
    if any(nested_value(event, "payload", "matchCount") == 0 for event in selection_results):
        return {"code": "SECTION_NOT_PRESENT_IN_SELECTED_LAYER", "detail": selection_results}
    persistence = events_named(attempts, "persistence-result")
    if persistence:
        return {"code": "MATCH_REACHED_PERSISTENCE", "detail": persistence[-1]}
    return {"code": "FIRST_LOSS_NOT_AUTOMATICALLY_CLASSIFIED", "detail": selected_events(attempts)}


def events_named(attempts: Iterable[ArtifactAttempt], event_name: str) -> list[dict[str, Any]]:
    """Find one event kind across every attempt."""
    return [event for attempt in attempts for event in attempt.events if event.get("eventName") == event_name]


def command_result_evidence(result: CommandResult, include_output: bool = False) -> dict[str, Any]:
    """Project command outcome without embedding SQL in the concise status section."""
    evidence: dict[str, Any] = {
        "executable": result.command[0] if result.command else None,
        "returnCode": result.return_code,
        "elapsedSeconds": result.elapsed_seconds,
        "stderr": result.stderr,
    }
    if include_output:
        evidence["stdout"] = result.stdout
    return evidence


def raw_artifact_evidence(
    attempts: list[ArtifactAttempt],
    database: CommandResult,
    journal: CommandResult,
    systemd: CommandResult,
) -> str:
    """Retain exact JSONL plus integrity and timing evidence in the final section."""
    header = json_text(
        {
            "attempts": attempt_inventory(attempts),
            "commandTimingsSeconds": {
                "database": database.elapsed_seconds,
                "journal": journal.elapsed_seconds,
                "systemd": systemd.elapsed_seconds,
            },
        }
    )
    chunks = [header]
    for index, attempt in enumerate(attempts, start=1):
        chunks.append(f"--- RAW JSONL ATTEMPT {index}: {attempt.directory.name} ---\n{attempt.raw_text}")
    return "\n\n".join(chunks)


def attempt_inventory(attempts: Iterable[ArtifactAttempt]) -> list[dict[str, Any]]:
    """Describe integrity and completion of every discovered attempt."""
    inventory: list[dict[str, Any]] = []
    for attempt in attempts:
        terminal = next(
            (event for event in reversed(attempt.events) if event.get("eventName") == "complete"),
            None,
        )
        inventory.append(
            {
                "directory": str(attempt.directory),
                "eventFile": str(attempt.event_file),
                "sha256": attempt.sha256,
                "eventCount": len(attempt.events),
                "errors": attempt.errors,
                "terminal": terminal,
            }
        )
    return inventory


def command_evidence(result: CommandResult) -> str:
    """Include command status, output, and stable failure type without shell interpolation."""
    return f"{command_status(result)}\n\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"


def command_status(result: CommandResult) -> str:
    """Render one command's identity and exit status."""
    return json_text({"command": result.command, "returnCode": result.return_code})


def default_output_path(implementation_task_id: int, output_directory: Path = DEFAULT_OUTPUT_ROOT) -> Path:
    """Choose a single timestamped report in /tmp for easy copying."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return output_directory / f"rule-positioning-forensics-impltask-{implementation_task_id}-{stamp}.txt"


def write_report(path: Path, report: str) -> None:
    """Create the report with owner-only permissions and replace no existing file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(report)
    restore_sudo_owner(path)


def restore_sudo_owner(path: Path) -> None:
    """Give a sudo-created report to the invoking operator when IDs are available."""
    user_id = os.environ.get("SUDO_UID")
    group_id = os.environ.get("SUDO_GID")
    if effective_user_id() != 0 or not user_id or not group_id:
        return
    try:
        os.chown(path, int(user_id), int(group_id))
    except (OSError, ValueError):
        return


def effective_user_id() -> int:
    """Return the Unix effective user ID, or a non-root sentinel elsewhere."""
    getter = getattr(os, "geteuid", None)
    return getter() if getter is not None else -1


def collect(arguments: argparse.Namespace) -> Path:
    """Collect every source and write exactly one report document."""
    attempt_paths = discover_attempts(arguments.artifact_root, arguments.implementation_task_id)
    attempts = [load_attempt(path) for path in attempt_paths]
    window = event_time_window(attempts)
    database_result = run_command(database_command(arguments.database, arguments.implementation_task_id), 120)
    journal_result = run_command(journal_command(arguments.service, window, arguments.implementation_task_id), 120)
    systemd_result = run_command(systemd_command(arguments.service), 30)
    end_database_result = run_command(database_command(arguments.database, arguments.implementation_task_id), 120)
    report = build_report(
        arguments.implementation_task_id,
        attempts,
        database_result,
        journal_result,
        systemd_result,
        end_database_result,
    )
    output_path = arguments.output or default_output_path(
        arguments.implementation_task_id,
        arguments.output_dir or DEFAULT_OUTPUT_ROOT,
    )
    write_report(output_path, report)
    return output_path


def main(arguments: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parsed = parse_arguments(arguments)
    try:
        output_path = collect(parsed)
    except (OSError, ValueError) as exception:
        sys.stderr.write(f"collector failed: {type(exception).__name__}: {exception}\n")
        return 1
    sys.stdout.write(f"{output_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
