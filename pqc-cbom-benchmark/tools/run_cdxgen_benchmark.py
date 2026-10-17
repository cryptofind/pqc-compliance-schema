#!/usr/bin/env python3
"""Run and score the H1-H9 Python targets with cdxgen."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = ROOT / "ground_truth"
TARGETS = ROOT / "targets"
DEFAULT_MANIFEST = ROOT / "cdxgen_manifest.json"
DEFAULT_RESULTS = ROOT / "results" / "cdxgen"
EXPECTED_STATUSES = {"active", "unreachable", "dead-branch"}
SCORED_HYPOTHESES = {f"H{i}" for i in range(1, 10)}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def normalize_algorithm(name: str) -> str:
    """Case- and punctuation-insensitive form used for exact algorithm matching."""
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def build_manifest() -> dict:
    cases = []
    for ground_truth_path in sorted(GROUND_TRUTH.glob("h*.json")):
        document = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        case_id = document["hypothesis"]
        if case_id not in SCORED_HYPOTHESES:
            continue

        expected_by_normalized_name = {}
        excluded = []
        for item in document["items"]:
            asset = item.get("asset")
            if not asset:
                continue
            name = asset["name"]
            if item["status"] in EXPECTED_STATUSES:
                expected_by_normalized_name.setdefault(normalize_algorithm(name), name)
            else:
                excluded.append({
                    "algorithm": name,
                    "ground_truth_id": item["id"],
                    "status": item["status"],
                    "reason": (
                        "reported separately as registry over-approximation"
                        if item["status"] == "registry"
                        else "identity/status is not part of the primary expected set"
                    ),
                })

        cases.append({
            "case_id": case_id,
            "target": document["target"],
            "language": "python",
            "scenario": document["question"],
            "expected_algorithms": list(expected_by_normalized_name.values()),
            "excluded_ground_truth": excluded,
            "ground_truth_file": f"ground_truth/{ground_truth_path.name}",
        })

    if {case["case_id"] for case in cases} != SCORED_HYPOTHESES:
        raise RuntimeError("Ground truth must define exactly H1-H9 before generating the manifest.")
    return {
        "schema": "pqc-cbom-benchmark/cdxgen-manifest/1",
        "generated_from": "ground_truth/h01.json through ground_truth/h09.json",
        "expected_algorithm_rule": (
            "Unique asset.name values from ground truth items with status active, unreachable, "
            "or dead-branch. Conditional runtime items remain expected because cdxgen scans source. "
            "Registry and unresolved items are listed separately and excluded from primary scores."
        ),
        "normalization": "casefold, then remove all non-ASCII-alphanumeric characters",
        "cases": cases,
    }


def write_manifest(path: Path) -> None:
    manifest = build_manifest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def algorithm_candidates(component: dict) -> tuple[set[str], list[str]]:
    crypto_properties = component.get("cryptoProperties") or {}
    algorithm_properties = crypto_properties.get("algorithmProperties") or {}
    raw_names = []
    for value in (
        algorithm_properties.get("variant"),
        algorithm_properties.get("parameterSetIdentifier"),
        component.get("name"),
    ):
        if isinstance(value, str) and value.strip():
            raw_names = [value.strip()]
            break
    names = {normalize_algorithm(name) for name in raw_names}
    return names, raw_names


def score_case(expected: list[str], registry_excluded: list[str], bom: dict | None) -> dict:
    components = (bom or {}).get("components", [])
    detected = set()
    unlabeled_count = 0
    registry_names = set()
    for component in components:
        if component.get("type") != "cryptographic-asset":
            continue
        names, raw_names = algorithm_candidates(component)
        if not names:
            unlabeled_count += 1
        detected.update(names)
        if raw_names:
            registry_names.update(names)

    expected_by_normalized = {normalize_algorithm(name): name for name in expected}
    registry_by_normalized = {normalize_algorithm(name): name for name in registry_excluded}
    true_positive_keys = set(expected_by_normalized) & detected
    registry_overapproximation_keys = set(registry_by_normalized) & detected
    false_positive_keys = detected - set(expected_by_normalized) - set(registry_by_normalized)
    missed_keys = set(expected_by_normalized) - detected
    true_positives = [expected_by_normalized[key] for key in sorted(true_positive_keys)]
    missed = [expected_by_normalized[key] for key in sorted(missed_keys)]
    false_positives = sorted(false_positive_keys)
    precision = (
        len(true_positives) / (len(true_positives) + len(false_positives))
        if true_positives or false_positives
        else None
    )
    recall = len(true_positives) / len(expected) if expected else None
    return {
        "expected_algorithms": expected,
        "detected_algorithms": sorted(detected),
        "true_positives": true_positives,
        "registry_overapproximation_algorithms": [
            registry_by_normalized[key] for key in sorted(registry_overapproximation_keys)
        ],
        "false_positives": false_positives,
        "missed_algorithms": missed,
        "tp": len(true_positives),
        "fp": len(false_positives),
        "missed": len(missed),
        "recall": recall,
        "precision": precision,
        "cryptographic_asset_component_count": sum(
            1 for component in components if component.get("type") == "cryptographic-asset"
        ),
        "unlabeled_crypto_asset_component_count": unlabeled_count,
    }


def read_bom(path: Path) -> tuple[dict | None, str | None]:
    if not path.is_file():
        return None, "BOM file was not created"
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"BOM could not be parsed: {exc}"
    if not isinstance(bom, dict) or not isinstance(bom.get("components"), list):
        return None, "BOM is not a JSON object with a components array"
    return bom, None


def command_display(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv) if sys.platform == "win32" else subprocess.list2cmdline(argv)


def clean_output(value: str) -> str:
    return ANSI_ESCAPE.sub("", value).strip()


def invoke(argv: list[str], log_path: Path) -> tuple[int, float, str, str]:
    start = time.perf_counter()
    try:
        if sys.platform == "win32":
            process = subprocess.run(
                command_display(argv),
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        else:
            process = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        exit_code = process.returncode
        stdout, stderr = process.stdout, process.stderr
    except OSError as exc:
        exit_code, stdout, stderr = 127, "", str(exc)
    elapsed = time.perf_counter() - start
    log_path.write_text(
        f"$ {command_display(argv)}\n\n[stdout]\n{stdout}\n[stderr]\n{stderr}",
        encoding="utf-8",
    )
    return exit_code, elapsed, stdout, stderr


def markdown_report(summary: dict) -> str:
    lines = [
        "# cdxgen PQC benchmark results",
        "",
        f"- Run: `{summary['run_id']}`",
        f"- cdxgen version: `{summary['cdxgen_version']}`",
        f"- Cases: {summary['case_count']}",
        f"- Successful scans: {summary['successful_scan_count']}/{summary['case_count']}",
        f"- Cases with at least one algorithm detection: {summary['cases_with_algorithm_detection']}/{summary['case_count']}",
        f"- `cryptographic-asset` components: {summary['cryptographic_asset_component_count']}",
        f"- Aggregate TP / FP / missed: {summary['totals']['tp']} / {summary['totals']['fp']} / {summary['totals']['missed']}",
        f"- Micro recall / precision: {format_metric(summary['micro_recall'])} / {format_metric(summary['micro_precision'])}",
        "",
        "A successful scan means cdxgen exited with code 0 and produced a parseable BOM. "
        "Algorithm detection is scored separately using only components whose type is "
        "`cryptographic-asset`; ordinary dependencies do not count.",
        "",
        "| Case | Scan | TP | FP | Missed | Recall | Precision | Runtime (s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for case in summary["cases"]:
        scan = "OK" if case["scan_succeeded"] else "FAILED"
        lines.append(
            f"| {case['case_id']} | {scan} | {case['tp']} | {case['fp']} | {case['missed']} | "
            f"{format_metric(case['recall'])} | {format_metric(case['precision'])} | {case['runtime_seconds']:.2f} |"
        )

    lines.extend(["", "## Per-case details", ""])
    for case in summary["cases"]:
        lines.extend([
            f"### {case['case_id']} — {case['scenario']}",
            "",
            f"- Target: `{case['target']}`",
            f"- Command: `{case['command']}`",
            f"- Exit code: `{case['exit_code']}`; scan succeeded: `{str(case['scan_succeeded']).lower()}`; "
            f"algorithm detection succeeded: `{str(case['algorithm_detection_succeeded']).lower()}`",
            f"- BOM: `{case['bom_path']}`",
            f"- Log: `{case['log_path']}`",
            f"- Result: `{case['result_path']}`",
            f"- Detected (normalized): {format_names(case['detected_algorithms'])}",
            f"- True positives: {format_names(case['true_positives'])}",
            f"- Registry over-approximation: {format_names(case['registry_overapproximation_algorithms'])}",
            f"- False positives (normalized): {format_names(case['false_positives'])}",
            f"- Missed: {format_names(case['missed_algorithms'])}",
        ])
        if case["scan_error"]:
            lines.append(f"- Scan/BOM issue: {case['scan_error']}")
        if case["log_diagnostics"]:
            lines.append("- Log diagnostics: " + " | ".join(f"`{item}`" for item in case["log_diagnostics"]))
        lines.append("")
    unsupported_diagnostics = [
        diagnostic
        for case in summary["cases"]
        for diagnostic in case["log_diagnostics"]
        if re.search(r"unsupported|not supported", diagnostic, flags=re.IGNORECASE)
    ]
    limitation = (
        f"Across these scans, cdxgen produced {summary['cryptographic_asset_component_count']} "
        "`cryptographic-asset` components. "
    )
    limitation += (
        "The BOMs contained dependency components only. "
        if summary["cryptographic_asset_component_count"] == 0
        else ""
    )
    limitation += (
        "No missing BOMs were observed. "
        if summary["missing_or_invalid_bom_count"] == 0
        else f"{summary['missing_or_invalid_bom_count']} case(s) had no parseable BOM. "
    )
    limitation += (
        "No explicit unsupported-pattern diagnostics were found in the logs. "
        if not unsupported_diagnostics
        else "Unsupported-pattern diagnostics were found in logs; review the per-case log diagnostics. "
    )
    lines.extend([
        "## Scoring and limitations",
        "",
        "Names are case-folded and stripped of non-alphanumeric characters before exact set matching. "
        "Expected names come from the ground-truth manifest, not from cdxgen output. The manifest includes "
        "resolved active, unreachable, and dead-branch ground-truth assets; runtime-conditional items are "
        "included because this benchmark scans source rather than executing it. Registry entries and "
        "unresolved identities are recorded in the manifest but excluded from primary TP/FP/missed scores.",
        "",
        "A clean scan does not prove an application works; this benchmark invokes cdxgen only and does not "
        "run the target applications. A zero-detection case can still be a successful scan. Review each "
        "case log for cdxgen warnings or unsupported-pattern indications; no unsupported pattern is inferred "
        "solely from a missed detection.",
        "",
        limitation,
        "A zero count of `cryptographic-asset` components means the detector emitted no algorithm components "
        "under the required scoring rule. This is not a claim that the target applications failed at runtime.",
        "",
    ])
    return "\n".join(lines)


def format_metric(value) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def format_names(names: list[str]) -> str:
    return ", ".join(f"`{name}`" for name in names) if names else "None"


def run(manifest_path: Path, results_root: Path) -> Path:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "pqc-cbom-benchmark/cdxgen-manifest/1":
        raise ValueError(f"Unsupported manifest schema: {manifest.get('schema')!r}")
    executable = shutil.which("cdxgen")
    if not executable:
        raise FileNotFoundError("cdxgen was not found on PATH")

    run_timestamp = datetime.now(timezone.utc)
    run_id = run_timestamp.strftime("%Y%m%dT%H%M%SZ")
    run_dir = results_root / run_id
    if run_dir.exists():
        raise FileExistsError(f"Run directory already exists; refusing to overwrite: {run_dir}")
    run_dir.mkdir(parents=True)
    version_exit, _, version_stdout, version_stderr = invoke(
        [executable, "--version"],
        run_dir / "cdxgen-version.log",
    )
    if version_exit != 0:
        raise RuntimeError(f"cdxgen --version failed: {version_stderr.strip()}")
    version = clean_output(version_stdout) or clean_output(version_stderr)

    shutil.copy2(manifest_path, run_dir / "manifest.json")
    (run_dir / "cdxgen-version.txt").write_text(
        f"{version}\n", encoding="utf-8"
    )

    case_records = []
    for case in manifest["cases"]:
        case_dir = run_dir / case["case_id"].lower()
        case_dir.mkdir()
        target_path = (ROOT / case["target"]).resolve()
        bom_path = case_dir / "bom.json"
        log_path = case_dir / "cdxgen.log"
        result_path = case_dir / "result.json"
        command = [executable, "--include-crypto", "-o", str(bom_path), str(target_path)]
        timestamp = datetime.now(timezone.utc).isoformat()
        exit_code, runtime_seconds, stdout, stderr = invoke(command, log_path)
        bom, bom_error = read_bom(bom_path)
        registry_names = [
            item["algorithm"]
            for item in case.get("excluded_ground_truth", [])
            if item["status"] == "registry"
        ]
        scored = score_case(case["expected_algorithms"], registry_names, bom)
        log_diagnostics = sorted({
            clean_output(line)
            for line in (stdout + "\n" + stderr).splitlines()
            if re.search(
                r"warning|notice|unable to identify|unsupported|not supported|error|failed",
                line,
                flags=re.IGNORECASE,
            )
        })
        scan_succeeded = exit_code == 0 and bom is not None
        record = {
            "schema": "pqc-cbom-benchmark/cdxgen-case-result/1",
            "case_id": case["case_id"],
            "target": case["target"],
            "language": case["language"],
            "scenario": case["scenario"],
            "run_timestamp_utc": timestamp,
            "cdxgen_version": version,
            "command": command,
            "command_display": command_display(command),
            "exit_code": exit_code,
            "runtime_seconds": round(runtime_seconds, 6),
            "scan_succeeded": scan_succeeded,
            "algorithm_detection_succeeded": scored["tp"] > 0,
            "all_expected_algorithms_detected": scored["missed"] == 0,
            "scan_error": bom_error if bom_error else (
                None if exit_code == 0 else f"cdxgen exited with code {exit_code}; inspect the log"
            ),
            "bom_error": bom_error,
            "log_diagnostics": log_diagnostics,
            "bom_path": str(bom_path.relative_to(run_dir)),
            "log_path": str(log_path.relative_to(run_dir)),
            "result_path": str(result_path.relative_to(run_dir)),
            **scored,
        }
        result_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        case_records.append(record)

    total_tp = sum(case["tp"] for case in case_records)
    total_fp = sum(case["fp"] for case in case_records)
    total_missed = sum(case["missed"] for case in case_records)
    total_expected = sum(len(case["expected_algorithms"]) for case in case_records)
    total_detections = total_tp + total_fp
    summary = {
        "schema": "pqc-cbom-benchmark/cdxgen-summary/1",
        "run_id": run_id,
        "run_timestamp_utc": run_timestamp.isoformat(),
        "cdxgen_version": version,
        "manifest": str(manifest_path),
        "case_count": len(case_records),
        "successful_scan_count": sum(case["scan_succeeded"] for case in case_records),
        "cases_with_algorithm_detection": sum(case["algorithm_detection_succeeded"] for case in case_records),
        "all_expected_algorithms_detected_count": sum(case["all_expected_algorithms_detected"] for case in case_records),
        "cryptographic_asset_component_count": sum(
            case["cryptographic_asset_component_count"] for case in case_records
        ),
        "missing_or_invalid_bom_count": sum(case["bom_error"] is not None for case in case_records),
        "totals": {"tp": total_tp, "fp": total_fp, "missed": total_missed, "expected": total_expected},
        "micro_recall": total_tp / total_expected if total_expected else None,
        "micro_precision": total_tp / total_detections if total_detections else None,
        "cases": case_records,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(markdown_report(summary), encoding="utf-8")
    return run_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument(
        "--write-manifest",
        action="store_true",
        help="create a fresh manifest from the repository ground truth, then exit",
    )
    args = parser.parse_args()
    if args.write_manifest:
        if args.manifest.exists():
            raise FileExistsError(f"Manifest already exists; refusing to overwrite: {args.manifest}")
        write_manifest(args.manifest)
        print(f"[cdxgen] manifest written: {args.manifest}")
        return 0
    run_dir = run(args.manifest.resolve(), args.results_dir.resolve())
    print(f"[cdxgen] results: {run_dir}")
    print(f"[cdxgen] summary: {run_dir / 'summary.json'}")
    print(f"[cdxgen] report: {run_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
