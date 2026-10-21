#!/usr/bin/env python3
"""Generates targets/h07_call_depth for hypothesis H7 (call depth).  Never scan this file.

Depth d counts the call boundaries between the entry function (tracks A, E) or the literal
that fixes the key size (tracks B, C, D) and the cryptographic API call.
Running this script overwrites the target directory.
"""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "targets" / "h07_call_depth"

DEPTHS_A = (0, 1, 2, 3, 4, 6, 8, 12, 16)
CURVES_A = {0: "SECP256R1", 1: "SECP384R1", 2: "SECP521R1", 3: "SECP224R1", 4: "SECP256K1",
            6: "BrainpoolP256R1", 8: "BrainpoolP384R1", 12: "BrainpoolP512R1", 16: "SECP192R1"}
DEPTHS_B = (0, 1, 2, 3, 4, 6, 8, 12, 16)
SIZES_B = {0: 2048, 1: 3072, 2: 4096, 3: 2048, 4: 3072, 6: 4096, 8: 2048, 12: 3072, 16: 4096}
DEPTHS_C = (1, 2, 4, 8)
SIZES_C = {1: 4096, 2: 2048, 4: 3072, 8: 4096}
DEPTHS_D = (1, 2, 4)
SIZES_D = {1: 3072, 2: 2048, 4: 4096}
DEPTHS_E = (0, 4, 16)

RSA_CALL = "rsa.generate_private_key(public_exponent=65537, key_size={arg})"


def _blocks(*blocks) -> str:
    out = []
    for block in blocks:
        out.extend(block)
        out.extend(["", ""])
    return "\n".join(out).rstrip() + "\n"


def _chain(prefix: str, d: int) -> list[str]:
    return [f"_{prefix}_d{d:02d}_h{k:02d}" for k in range(1, d)] + [f"_{prefix}_d{d:02d}_sink"]


def _local_track(prefix: str, depths, doc: str, imports: str, body) -> str:
    head = [f'"""{doc}"""', imports]
    entries, hops, sinks = [], [], []
    for d in depths:
        if d == 0:
            entries.append([f"def {prefix}_entry_d00():"] + body(d))
            continue
        chain = _chain(prefix, d)
        entries.append([f"def {prefix}_entry_d{d:02d}():", f"    return {chain[0]}()"])
        hops += [[f"def {a}():", f"    return {b}()"] for a, b in zip(chain[:-1], chain[1:])]
        sinks.append([f"def {chain[-1]}():"] + body(d))
    return _blocks(head, *entries, *hops, *sinks)


def track_a() -> str:
    def body(d):
        c, m = CURVES_A[d], f"GT:H7-A-d{d:02d}"
        return [f"    mine = ec.generate_private_key(ec.{c}())  # {m}/keygen",
                f"    peer = ec.generate_private_key(ec.{c}())  # {m}/keygen",
                f"    return mine.exchange(ec.ECDH(), peer.public_key())  # {m}/op"]
    return _local_track("a", DEPTHS_A, "H7 track A: the cryptographic call is local to the deepest function of each chain.",
                        "from cryptography.hazmat.primitives.asymmetric import ec", body)


def track_e() -> str:
    def body(d):
        m = f"GT:H7-E-d{d:02d}"
        return [f"    receiver = mlkem.MLKEM768PrivateKey.generate()  # {m}/keygen",
                f"    shared, encapsulated = receiver.public_key().encapsulate()  # {m}/op",
                "    return receiver.decapsulate(encapsulated) == shared"]
    return _local_track("e", DEPTHS_E, "H7 track E: post-quantum key establishment local to the deepest function.",
                        "from cryptography.hazmat.primitives.asymmetric import mlkem", body)


def track_b() -> str:
    head = ['"""H7 track B: a key-size literal travels through d calls before it reaches the API call."""',
            "from cryptography.hazmat.primitives.asymmetric import rsa"]
    entries, hops, sinks = [], [], []
    for d in DEPTHS_B:
        m = f"GT:H7-B-d{d:02d}"
        if d == 0:
            entries.append(["def b_entry_d00():", f"    return {RSA_CALL.format(arg=SIZES_B[0])}  # {m}"])
            continue
        chain = _chain("b", d)
        entries.append([f"def b_entry_d{d:02d}():", f"    return {chain[0]}({SIZES_B[d]})  # {m}/src"])
        hops += [[f"def {a}(bits):", f"    return {b}(bits)"] for a, b in zip(chain[:-1], chain[1:])]
        sinks.append([f"def {chain[-1]}(bits):", f"    return {RSA_CALL.format(arg='bits')}  # {m}"])
    return _blocks(head, *entries, *hops, *sinks)


def track_c() -> dict[str, str]:
    files = {"xmod/__init__.py": '"""Cross-module relay package for H7 track C."""\n'}
    files["xmod/sinks.py"] = _blocks(
        ['"""H7 track C sinks."""', "from cryptography.hazmat.primitives.asymmetric import rsa"],
        *[[f"def c_d{d:02d}(bits):", f"    return {RSA_CALL.format(arg='bits')}  # GT:H7-C-d{d:02d}"] for d in DEPTHS_C])
    for level in range(1, max(DEPTHS_C)):
        chains = [d for d in DEPTHS_C if d - 1 >= level]
        nxt = {d: (f"level{level + 1:02d}" if level + 1 <= d - 1 else "sinks") for d in chains}
        files[f"xmod/level{level:02d}.py"] = _blocks(
            [f'"""H7 track C relay level {level}."""', f"from xmod import {', '.join(sorted(set(nxt.values())))}"],
            *[[f"def c_d{d:02d}(bits):", f"    return {nxt[d]}.c_d{d:02d}(bits)"] for d in chains])
    first = {d: ("level01" if d > 1 else "sinks") for d in DEPTHS_C}
    files["track_c.py"] = _blocks(
        ['"""H7 track C: the key-size literal crosses one module boundary per call."""',
         f"from xmod import {', '.join(sorted(set(first.values())))}"],
        *[[f"def c_entry_d{d:02d}():", f"    return {first[d]}.c_d{d:02d}({SIZES_C[d]})  # GT:H7-C-d{d:02d}/src"] for d in DEPTHS_C])
    return files


def track_d() -> str:
    head = ['"""H7 track D: the key size is stored on objects and read back after d object hops."""',
            "from cryptography.hazmat.primitives.asymmetric import rsa"]
    entries, classes = [], []
    for d in DEPTHS_D:
        entries.append([f"def d_entry_d{d:02d}():", f"    return D{d:02d}Hop01({SIZES_D[d]}).run()  # GT:H7-D-d{d:02d}/src"])
        for k in range(1, d + 1):
            last = (f"        return {RSA_CALL.format(arg='self.bits')}  # GT:H7-D-d{d:02d}" if k == d
                    else f"        return D{d:02d}Hop{k + 1:02d}(self.bits).run()")
            classes.append([f"class D{d:02d}Hop{k:02d}:", "    def __init__(self, bits):", "        self.bits = bits",
                            "", "    def run(self):", last])
    return _blocks(head, *entries, *classes)


def main_py() -> str:
    calls = ([f"    track_a.a_entry_d{d:02d}()" for d in DEPTHS_A] + [f"    track_b.b_entry_d{d:02d}()" for d in DEPTHS_B]
             + [f"    track_c.c_entry_d{d:02d}()" for d in DEPTHS_C] + [f"    track_d.d_entry_d{d:02d}()" for d in DEPTHS_D]
             + [f"    track_e.e_entry_d{d:02d}()" for d in DEPTHS_E])
    return _blocks(['"""Benchmark target H7: call depth (generated by tools/gen_h07.py; do not edit by hand)."""',
                    "import probe", "import track_a", "import track_b", "import track_c", "import track_d", "import track_e"],
                   ["def main() -> int:", "    probe.probe()", *calls, '    print("[h07] done")', "    return 0"],
                   ['if __name__ == "__main__":', "    raise SystemExit(main())"])


def generate() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "xmod").mkdir(parents=True)
    files = {"track_a.py": track_a(), "track_b.py": track_b(), "track_d.py": track_d(), "track_e.py": track_e(),
             "main.py": main_py(), "requirements.txt": "cryptography==50.0.2\n", **track_c()}
    for rel, text in files.items():
        (OUT / rel).write_text(text)
    shutil.copy(ROOT / "tools" / "_probe_template.py", OUT / "probe.py")


if __name__ == "__main__":
    generate()
    print(f"wrote {OUT.relative_to(ROOT)}")
