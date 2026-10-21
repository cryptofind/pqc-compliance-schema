"""Benchmark target H9: graded evidence and decoys for confidence scoring."""
import decoys
import evidence_ladder
import probe


def main() -> int:
    probe.probe()
    evidence_ladder.c1_literal(b"h09")
    evidence_ladder.c2_constant(b"h09")
    evidence_ladder.c3_single_caller()
    evidence_ladder.c4_path_dependent(b"h09")
    evidence_ladder.c5_string_resolved(b"h09")
    evidence_ladder.c6_external(b"h09")
    evidence_ladder.c8_dead_branch(b"h09")
    evidence_ladder.c9_non_security(b"h09")
    decoys.rotate_keys()
    decoys.ECDSA("ECN-7").sign("reviewer")  # GT:H9-D2/decoy
    decoys.sha256_digest(b"h09")  # GT:H9-D4/decoy
    decoys.describe()
    print("[h09] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
