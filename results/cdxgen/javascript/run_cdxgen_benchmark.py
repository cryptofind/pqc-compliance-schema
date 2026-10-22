#!/usr/bin/env python3
"""Run cdxgen on the JavaScript H1-H9 targets and score algorithm components."""
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

ROOT = Path(__file__).resolve().parents[3]
GROUND_TRUTH = ROOT / "python" / "ground_truth"
TARGETS = ROOT / "javascript" / "targets"
DEFAULT_MANIFEST = ROOT / "javascript" / "cdxgen_manifest.json"
DEFAULT_RESULTS = ROOT / "results" / "cdxgen" / "javascript" / "runs"
HYPOTHESES = {f"H{i}" for i in range(1, 10)}
EXPECTED_STATUSES = {"active", "unreachable", "dead-branch"}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def build_manifest() -> dict:
    cases = []
    for path in sorted(GROUND_TRUTH.glob("h*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        case_id = document["hypothesis"]
        if case_id not in HYPOTHESES:
            continue
        expected = {}
        excluded = []
        for item in document["items"]:
            asset = item.get("asset")
            if not asset:
                continue
            name = asset["name"]
            if item["status"] in EXPECTED_STATUSES:
                expected.setdefault(normalize(name), name)
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
            "target": f"javascript/targets/{Path(document['target']).name}",
            "language": "javascript",
            "scenario": document["question"],
            "expected_algorithms": list(expected.values()),
            "excluded_ground_truth": excluded,
            "ground_truth_file": f"python/ground_truth/{path.name}",
        })
    if {case["case_id"] for case in cases} != HYPOTHESES:
        raise RuntimeError("Ground truth must define exactly H1-H9.")
    return {
        "schema": "pqc-cbom-benchmark/cdxgen-manifest/1",
        "generated_from": "python/ground_truth/h01.json through h09.json",
        "language": "javascript",
        "expected_algorithm_rule": (
            "Unique asset.name values from Python ground truth items with status active, "
            "unreachable, or dead-branch. Conditional items remain expected because the "
            "scanner inspects source. Registry and unresolved items are excluded."
        ),
        "normalization": "casefold, then remove all non-ASCII-alphanumeric characters",
        "cases": cases,
    }


def write_manifest(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"Manifest already exists; refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_manifest(), indent=2) + "\n", encoding="utf-8")


def score(expected: list[str], excluded: list[dict], bom: dict | None) -> dict:
    detected = set()
    components = (bom or {}).get("components", [])
    unlabeled = 0
    for component in components:
        if component.get("type") != "cryptographic-asset":
            continue
        crypto = component.get("cryptoProperties") or {}
        algorithm = crypto.get("algorithmProperties") or {}
        candidate = next((
            value.strip()
            for value in (
                algorithm.get("variant"),
                algorithm.get("parameterSetIdentifier"),
                component.get("name"),
            )
            if isinstance(value, str) and value.strip()
        ), "")
        if candidate:
            detected.add(normalize(candidate))
        else:
            unlabeled += 1

    expected_names = {normalize(name): name for name in expected}
    registry_names = {
        normalize(item["algorithm"]): item["algorithm"]
        for item in excluded if item["status"] == "registry"
    }
    tp_keys = set(expected_names) & detected
    registry_keys = set(registry_names) & detected
    fp_keys = detected - set(expected_names) - set(registry_names)
    missed_keys = set(expected_names) - detected
    tp, fp, missed = len(tp_keys), len(fp_keys), len(missed_keys)
    return {
        "expected_algorithms": expected,
        "detected_algorithms_normalized": sorted(detected),
        "true_positives": [expected_names[key] for key in sorted(tp_keys)],
        "registry_overapproximation_algorithms": [registry_names[key] for key in sorted(registry_keys)],
        "false_positives_normalized": sorted(fp_keys),
        "missed_algorithms": [expected_names[key] for key in sorted(missed_keys)],
        "tp": tp,
        "fp": fp,
        "missed": missed,
        "recall": tp / len(expected) if expected else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "cryptographic_asset_component_count": sum(
            component.get("type") == "cryptographic-asset" for component in components
        ),
        "unlabeled_crypto_asset_component_count": unlabeled,
    }


def command_text(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv)


def invoke(argv: list[str], log_path: Path) -> tuple[int, float, str, str]:
    start = time.perf_counter()
    try:
        if sys.platform == "win32":
            process = subprocess.run(
                command_text(argv), shell=True, capture_output=True, text=True,
                encoding="utf-8", errors="replace", check=False,
            )
        else:
            process = subprocess.run(
                argv, capture_output=True, text=True, encoding="utf-8",
                errors="replace", check=False,
            )
        code, stdout, stderr = process.returncode, process.stdout, process.stderr
    except OSError as exc:
        code, stdout, stderr = 127, "", str(exc)
    elapsed = time.perf_counter() - start
    log_path.write_text(
        f"$ {command_text(argv)}\n\n[stdout]\n{stdout}\n[stderr]\n{stderr}",
        encoding="utf-8",
    )
    return code, elapsed, stdout, stderr


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


def run(manifest_path: Path, results_root: Path) -> Path:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "pqc-cbom-benchmark/cdxgen-manifest/1":
        raise ValueError(f"Unsupported manifest schema: {manifest.get('schema')!r}")
    executable = shutil.which("cdxgen")
    if not executable:
        raise FileNotFoundError("cdxgen was not found on PATH")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = results_root / run_id
    if run_dir.exists():
        raise FileExistsError(f"Run directory already exists; refusing to overwrite: {run_dir}")
    run_dir.mkdir(parents=True)
    version_code, _, version_out, version_err = invoke(
        [executable, "--version"], run_dir / "cdxgen-version.log"
    )
    if version_code != 0:
        raise RuntimeError(f"cdxgen --version failed: {version_err.strip()}")
    version = ANSI_ESCAPE.sub("", (version_out or version_err).strip())
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (run_dir / "cdxgen-version.txt").write_text(version + "\n", encoding="utf-8")

    records = []
    for case in manifest["cases"]:
        case_dir = run_dir / case["case_id"].lower()
        case_dir.mkdir()
        bom_path, log_path = case_dir / "bom.json", case_dir / "cdxgen.log"
        target = (ROOT / case["target"]).resolve()
        command = [executable, "--include-crypto", "--no-install-deps", "-o", str(bom_path), str(target)]
        timestamp = datetime.now(timezone.utc).isoformat()
        code, elapsed, stdout, stderr = invoke(command, log_path)
        bom, bom_error = read_bom(bom_path)
        scored = score(case["expected_algorithms"], case["excluded_ground_truth"], bom)
        diagnostics = sorted({
            ANSI_ESCAPE.sub("", line).strip()
            for line in (stdout + "\n" + stderr).splitlines()
            if re.search(r"warning|notice|unable|unsupported|not supported|error|failed", line, re.I)
        })
        succeeded = code == 0 and bom is not None
        record = {
            "case_id": case["case_id"],
            "target": case["target"],
            "language": case["language"],
            "scenario": case["scenario"],
            "command": command,
            "timestamp": timestamp,
            "exit_code": code,
            "runtime_seconds": elapsed,
            "scan_succeeded": succeeded,
            "algorithm_detection_succeeded": scored["tp"] > 0,
            "bom_path": str(bom_path.relative_to(run_dir)),
            "log_path": str(log_path.relative_to(run_dir)),
            "scan_error": bom_error,
            "log_diagnostics": diagnostics,
            **scored,
        }
        (case_dir / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        records.append(record)

    total_expected = sum(len(case["expected_algorithms"]) for case in manifest["cases"])
    totals = {
        key: sum(record[key] for record in records)
        for key in ("tp", "fp", "missed", "cryptographic_asset_component_count")
    }
    tp_fp = totals["tp"] + totals["fp"]
    summary = {
        "schema": "pqc-cbom-benchmark/cdxgen-run/1",
        "run_id": run_id,
        "language": "javascript",
        "cdxgen_version": version,
        "case_count": len(records),
        "successful_scan_count": sum(record["scan_succeeded"] for record in records),
        "cases_with_algorithm_detection": sum(record["algorithm_detection_succeeded"] for record in records),
        "expected_algorithm_count": total_expected,
        "cryptographic_asset_component_count": totals["cryptographic_asset_component_count"],
        "totals": {**totals, "expected": total_expected},
        "micro_recall": totals["tp"] / total_expected if total_expected else None,
        "micro_precision": totals["tp"] / tp_fp if tp_fp else None,
        "cases": records,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# cdxgen JavaScript PQC benchmark results",
        "",
        f"- Run: `{run_id}`",
        f"- cdxgen version: `{version}`",
        f"- Successful scans: {summary['successful_scan_count']}/{len(records)}",
        f"- Cases with algorithm detections: {summary['cases_with_algorithm_detection']}/{len(records)}",
        f"- Expected assets: {total_expected}",
        f"- Cryptographic-asset components: {totals['cryptographic_asset_component_count']}",
        f"- Aggregate TP / FP / missed: {totals['tp']} / {totals['fp']} / {totals['missed']}",
        f"- Micro recall / precision: {metric(summary['micro_recall'])} / {metric(summary['micro_precision'])}",
        "",
        "| Case | Scan | TP | FP | Missed | Recall | Runtime (s) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for record in records:
        lines.append(
            f"| {record['case_id']} | {'OK' if record['scan_succeeded'] else 'FAILED'} | "
            f"{record['tp']} | {record['fp']} | {record['missed']} | "
            f"{metric(record['recall'])} | {record['runtime_seconds']:.2f} |"
        )
    for record in records:
        lines.extend([
            "",
            f"## {record['case_id']} — {record['scenario']}",
            "",
            f"- Scan: `{'succeeded' if record['scan_succeeded'] else 'failed'}` (exit {record['exit_code']})",
            f"- True positives: {names(record['true_positives'])}",
            f"- False positives (normalized): {names(record['false_positives_normalized'])}",
            f"- Registry over-approximation: {names(record['registry_overapproximation_algorithms'])}",
            f"- Missed: {names(record['missed_algorithms'])}",
            f"- BOM: `{record['bom_path']}`; log: `{record['log_path']}`",
        ])
        if record["scan_error"]:
            lines.append(f"- Scan/BOM issue: {record['scan_error']}")
        if record["log_diagnostics"]:
            lines.append("- Diagnostics: " + " | ".join(f"`{item}`" for item in record["log_diagnostics"]))
    lines.extend([
        "",
        "## Interpretation",
        "",
        "Only CycloneDX components with `type=cryptographic-asset` count as algorithm detections. "
        "Names are case-folded and stripped of non-alphanumeric characters before exact matching. "
        "Expected names are derived from the existing Python ground truth, not from cdxgen output. "
        "Registry and unresolved identities are excluded from the primary score.",
        "",
        "This harness invokes cdxgen only; it does not install dependencies or execute the target "
        "applications. A successful scan is distinct from successful cryptographic-asset detection. "
        "The JavaScript corpus is a translated equivalent, not a byte-for-byte port or a controlled "
        "language-only experiment; source idioms also affect visibility.",
        "",
    ])
    (run_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    return run_dir


def metric(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def names(values: list[str]) -> str:
    return ", ".join(f"`{name}`" for name in values) if values else "None"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    if args.write_manifest:
        write_manifest(args.manifest)
        print(f"Wrote manifest: {args.manifest}")
        return 0
    run_dir = run(args.manifest, args.results_dir)
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    print(
        f"Run {summary['run_id']}: {summary['successful_scan_count']}/{summary['case_count']} scans "
        f"succeeded; {summary['totals']['tp']} TP, {summary['totals']['fp']} FP, "
        f"{summary['totals']['missed']} missed."
    )
    print(f"Report: {run_dir / 'report.md'}")
    return 0 if summary["successful_scan_count"] == summary["case_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
