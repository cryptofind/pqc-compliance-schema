"""Benchmark target H8: policy-discriminating corpus (verdicts differ across reference policies)."""
import classical
import hashing
import hybrid
import pqc
import probe
import symmetric


def main() -> int:
    probe.probe()
    for fn in (symmetric.p01, symmetric.p02, symmetric.p03,
               hashing.p04, hashing.p05, hashing.p06, hashing.p07, hashing.p08, hashing.p09, hashing.p10,
               pqc.p11, pqc.p12, pqc.p13, pqc.p14, pqc.p15, pqc.p16,
               classical.p17, classical.p18, classical.p19, classical.p20, classical.p21,
               hybrid.p22, hybrid.p23):
        fn()
    print("[h08] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
