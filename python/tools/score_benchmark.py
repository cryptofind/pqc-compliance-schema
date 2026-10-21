
import json
import re
import sys
from pathlib import Path
from collections import Counter

REPO = Path(r"C:\Users\saads\pqc-compliance-schema")
RESULTS = Path(r"C:\Users\saads\security-tools\results")
OUT = RESULTS / "pqc-cbom-scoring"

POLICIES = ["QR-STRICT", "QR-HYBRID", "CNSA2-LIKE", "IR8547-2031"]
EXCLUDED_STATUSES = {"registry", "unresolved", "unreachable", "dead-branch"}
ANCHOR_ROLES = {"anchor"}
DECOY_STATUSES = {"decoy"}


def load_json(path):
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def normalize(value):
    """Normalize names for comparison without treating punctuation as meaningful."""
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def component_records(cbom):
    """Return algorithm components only; do not count key-material components as algorithms."""
    records = []
    for component in cbom.get("components", []):
        crypto = component.get("cryptoProperties") or {}
        alg = crypto.get("algorithmProperties")
        if not isinstance(alg, dict):
            continue
        if crypto.get("assetType") not in (None, "algorithm"):
            continue

        contexts = crypto.get("detectionContext") or []
        name = component.get("name", "")
        variant = alg.get("variant", "")
        records.append({
            "name": name,
            "variant": variant,
            "algorithm": alg,
            "contexts": contexts,
            "component": component,
            "search_names": {
                normalize(name), normalize(variant)
            } - {""},
        })
    return records


def location_matches(gt_location, context):
    gt_file = str(gt_location.get("file", "")).replace("\\", "/").casefold()
    found_file = str(context.get("filePath", "")).replace("\\", "/").casefold()

    if not gt_file or not found_file:
        return False
    if not (found_file == gt_file or found_file.endswith("/" + gt_file)):
        return False

    target_line = gt_location.get("line")
    lines = context.get("lineNumbers") or []
    if target_line is None or not lines:
        return False

    try:
        target_line = int(target_line)
        lines = [int(x) for x in lines]
    except (ValueError, TypeError):
        return False

    return min(lines) - 1 <= target_line <= max(lines) + 1


def expected_names(item):
    asset = item.get("asset") or {}
    names = set()
    for key in ("name", "family"):
        value = asset.get(key)
        if value:
            names.add(normalize(value))

    # Include a few explicitly defined parameter names when present.
    for key in ("parameter_set", "curve"):
        value = asset.get(key)
        if value:
            names.add(normalize(value))

    return names - {""}


def name_grade(item, component):
    """
    Conservative automatic name grade:
      L0 = no finding at the expected location
      L1 = a name/family match
      L2 = a main parameter appears to match
      L3 = mode/padding/hash detail appears to match
    Uncertain identity matches are left for manual review.
    """
    asset = item.get("asset") or {}
    alg = component["algorithm"]
    actual_names = component["search_names"]
    expected = expected_names(item)

    if not actual_names or not expected:
        return "REVIEW", "insufficient algorithm-name evidence"

    # Exact normalized asset name is strongest evidence.
    expected_name = normalize(asset.get("name", ""))
    if expected_name and expected_name in actual_names:
        grade = "L2"
        details = []

        for key, cbom_key in (
            ("key_bits", "keyLength"),
            ("output_bits", "outputLength"),
        ):
            expected_value = asset.get(key)
            actual_value = alg.get(cbom_key)
            if expected_value is not None and actual_value is not None:
                try:
                    if int(expected_value) != int(actual_value):
                        grade = "REVIEW"
                        details.append(f"{key} mismatch")
                except (TypeError, ValueError):
                    grade = "REVIEW"
                    details.append(f"{key} not comparable")

        expected_mode = normalize(asset.get("mode", ""))
        actual_mode = normalize(alg.get("mode", ""))
        expected_padding = normalize(asset.get("padding", ""))
        actual_padding = normalize(alg.get("padding", ""))
        expected_hash = normalize(asset.get("hash", ""))
        actual_hash = normalize(alg.get("hashFunction", alg.get("hash", "")))

        details_match = True
        for expected_detail, actual_detail, label in (
            (expected_mode, actual_mode, "mode"),
            (expected_padding, actual_padding, "padding"),
            (expected_hash, actual_hash, "hash"),
        ):
            if expected_detail:
                if actual_detail == expected_detail:
                    continue
                if not actual_detail or actual_detail == "unknown":
                    details_match = False
                    details.append(f"{label} not established")
                else:
                    details_match = False
                    details.append(f"{label} differs")

        if details_match and any((expected_mode, expected_padding, expected_hash)):
            grade = "L3"
        elif details:
            grade = "L2"

        return grade, "; ".join(details) if details else "normalized asset name matches"

    # Family-only match is useful but not enough to claim exact identification.
    family = normalize(asset.get("family", ""))
    if family and any(family == name or family in name for name in actual_names):
        return "L1", "family-level name match"

    return "REVIEW", "finding at location, but algorithm identity is not confidently matched"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    all_reports = []
    all_errors = []

    for index in range(10):
        h = f"h{index:02d}"
        gt_path = REPO / "pqc-cbom-benchmark" / "ground_truth" / f"{h}.json"

        # Results folder names are h00_baseline, h01_metaprogramming, etc.
        candidates = sorted(RESULTS.glob(f"{h}_*"))
        cbom_paths = [p / f"{h}-cbom.json" for p in candidates]
        cbom_path = next((p for p in cbom_paths if p.is_file()), None)

        if not gt_path.is_file():
            all_errors.append(f"{h}: missing ground truth: {gt_path}")
            continue
        if cbom_path is None:
            all_errors.append(f"{h}: missing CBOM in {RESULTS}")
            continue

        try:
            gt = load_json(gt_path)
            cbom = load_json(cbom_path)
        except Exception as exc:
            all_errors.append(f"{h}: cannot read JSON: {exc}")
            continue

        items = gt.get("items", [])
        components = component_records(cbom)
        report_items = []
        grade_counts = Counter()
        status_counts = Counter()
        matched_ids = set()
        decoy_findings = []
        unattributed_findings = []

        # Ground-truth location matching, followed by conservative identity grading.
        for item in items:
            item_id = item.get("id", "UNKNOWN")
            status = item.get("status", "active")
            status_counts[status] += 1

            if status in EXCLUDED_STATUSES or status in DECOY_STATUSES:
                report_items.append({
                    "id": item_id,
                    "status": status,
                    "grade": "EXCLUDED_FROM_PRIMARY_RECALL",
                    "reason": "tracked separately; not counted as an ordinary positive target",
                })
                continue

            locations = [
                loc for loc in item.get("locations", [])
                if loc.get("role") not in ANCHOR_ROLES
            ]

            location_hits = []
            for component_index, component in enumerate(components):
                for context in component["contexts"]:
                    if any(location_matches(loc, context) for loc in locations):
                        location_hits.append((component_index, component))
                        break

            # Deduplicate multiple contexts for the same component.
            unique_hits = {}
            for component_index, component in location_hits:
                unique_hits[component_index] = component
            location_hits = list(unique_hits.values())

            if not location_hits:
                grade = "L0"
                reason = "no algorithm component matched a ground-truth location"
                grade_counts[grade] += 1
                report_items.append({
                    "id": item_id,
                    "status": status,
                    "grade": grade,
                    "reason": reason,
                    "expected_name": (item.get("asset") or {}).get("name"),
                })
                continue

            graded = [name_grade(item, component) for component in location_hits]
            grade_order = {"L0": 0, "REVIEW": 0, "L1": 1, "L2": 2, "L3": 3}
            best_index = max(
                range(len(graded)),
                key=lambda i: grade_order.get(graded[i][0], 0)
            )
            grade, reason = graded[best_index]
            best_component = location_hits[best_index]

            if grade == "REVIEW":
                grade_counts["REVIEW"] += 1
            else:
                grade_counts[grade] += 1
                matched_ids.add(item_id)

            report_items.append({
                "id": item_id,
                "status": status,
                "grade": grade,
                "reason": reason,
                "expected_name": (item.get("asset") or {}).get("name"),
                "observed_name": best_component["name"],
                "observed_variant": best_component["variant"],
                "location_hit_count": len(location_hits),
            })

        # A finding is not automatically a false positive just because it did not
        # match a target: decomposed algorithms and shared contexts require review.
        matched_component_signatures = set()
        for item in items:
            for loc in item.get("locations", []):
                if loc.get("role") in ANCHOR_ROLES:
                    continue
                for ci, component in enumerate(components):
                    if any(location_matches(loc, context) for context in component["contexts"]):
                        matched_component_signatures.add(ci)

        for ci, component in enumerate(components):
            if ci not in matched_component_signatures:
                unattributed_findings.append({
                    "name": component["name"],
                    "variant": component["variant"],
                    "review_required": True,
                    "note": "unmatched component; not automatically declared a false positive",
                })

        eligible = [
            item for item in items
            if item.get("status", "active") not in EXCLUDED_STATUSES | DECOY_STATUSES
            and not any(
                loc.get("role") in ANCHOR_ROLES
                for loc in item.get("locations", [])
            )
        ]
        denominator = len(eligible)
        definite_detected = sum(
            1 for row in report_items
            if row["id"] in {x.get("id") for x in eligible}
            and row["grade"] in {"L1", "L2", "L3"}
        )
        # REVIEW cases are not silently counted as hits or misses.
        report = {
            "hypothesis_id": h,
            "hypothesis": gt.get("hypothesis", h),
            "ground_truth_file": str(gt_path),
            "cbom_file": str(cbom_path),
            "ground_truth_item_count": len(items),
            "algorithm_component_count": len(components),
            "status_counts": dict(status_counts),
            "eligible_primary_targets": denominator,
            "definite_detected_L1_or_better": definite_detected,
            "definite_recall_percent": (
                round(100 * definite_detected / denominator, 2)
                if denominator else None
            ),
            "grade_counts": dict(grade_counts),
            "policy_verdicts_in_ground_truth": bool(gt.get("policies")),
            "special_metrics": {
                "H4": "unit-level policy agreement needs separate policy-output comparison",
                "H5": "paired misleading-vs-neutral analysis needs manual-confirmed identity matches",
                "H6": "configuration-source evidence requires separate source-location analysis",
                "H7": "deepest detected call depth requires mapping findings to track and depth",
                "H8": "unit-level policy agreement needs separate policy-output comparison",
                "H9": "confidence/evidence ranking requires extraction of confidence fields and review",
            }.get(h, "core detection scoring"),
            "items": report_items,
            "unattributed_findings_for_review": unattributed_findings,
            "limitations": [
                "Location match is not proof of correct algorithm identity.",
                "REVIEW grades are excluded from definite detection recall.",
                "Unattributed findings are not automatically labelled false positives.",
                "Policy, call-depth, config-source, paired-name and confidence metrics are not yet automatically scored.",
                "Ground truth is read-only; this script does not write to it.",
            ],
        }
        all_reports.append(report)

    json_path = OUT / "h00-h09-scoring.json"
    md_path = OUT / "h00-h09-scoring.md"

    summary = {
        "title": "H0-H9 CryptoBOM Benchmark Scoring",
        "method": "Conservative location matching and algorithm-name grading",
        "hypotheses_scored": len(all_reports),
        "errors": all_errors,
        "reports": all_reports,
    }
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# H0-H9 CryptoBOM Benchmark Scoring",
        "",
        "This is an initial automated scoring pass. Review cases and hypothesis-specific metrics are explicitly identified.",
        "",
        "| Hypothesis | Eligible targets | Definite detections | Recall | L1 | L2 | L3 | Review | Unattributed findings |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in all_reports:
        grades = r["grade_counts"]
        lines.append(
            f"| {r['hypothesis_id']} | {r['eligible_primary_targets']} "
            f"| {r['definite_detected_L1_or_better']} "
            f"| {r['definite_recall_percent']}% "
            f"| {grades.get('L1', 0)} | {grades.get('L2', 0)} "
            f"| {grades.get('L3', 0)} | {grades.get('REVIEW', 0)} "
            f"| {len(r['unattributed_findings_for_review'])} |"
        )

    lines.extend(["", "## Important limitations", ""])
    lines.extend(f"- {error}" for error in all_errors)
    lines.extend([
        "- A location match is not sufficient proof of correct identification.",
        "- Review cases are excluded from definite recall.",
        "- Unattributed findings require review and are not automatically false positives.",
        "- H4/H8 policy agreement, H5 paired comparisons, H6 configuration evidence, H7 depth, and H9 confidence require additional targeted analyses.",
        "- Ground-truth files are read-only and are never modified.",
    ])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Hypotheses scored: {len(all_reports)}/10")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    if all_errors:
        print("\nWarnings/errors:")
        for error in all_errors:
            print(f" - {error}")
    print("\nSummary:")
    for r in all_reports:
        print(
            f"{r['hypothesis_id']}: recall={r['definite_recall_percent']}%, "
            f"targets={r['eligible_primary_targets']}, "
            f"detected={r['definite_detected_L1_or_better']}, "
            f"review={r['grade_counts'].get('REVIEW', 0)}"
        )

    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
