"""Benchmark target H0: direct-use baseline (control for every algorithm and library used in H1-H9)."""
import os

import direct_asymmetric
import direct_hash_mac_kdf
import direct_pqc
import direct_stdlib
import direct_symmetric
import direct_third_party
import probe

try:
    import alt_pqcrypto
except ImportError:
    alt_pqcrypto = None
try:
    import alt_pure_python
except ImportError:
    alt_pure_python = None
alt_liboqs = None
if os.environ.get("H00_WITH_LIBOQS") == "1":
    import alt_liboqs


def main() -> int:
    probe.probe()
    for module in (direct_symmetric, direct_hash_mac_kdf, direct_asymmetric, direct_pqc, direct_stdlib, direct_third_party):
        module.run()
    for module in (alt_pqcrypto, alt_pure_python, alt_liboqs):
        if module is not None:
            module.run()
    print("[h00] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
