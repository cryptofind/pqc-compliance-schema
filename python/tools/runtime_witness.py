#!/usr/bin/env python3
"""Runtime witness for the benchmark targets (Python >= 3.12, uses sys.monitoring).

Runs a target's main.py and records every source line of the target that calls into a watched
cryptographic library.  Calls made by code compiled from strings (exec/eval) are attributed to the
nearest enclosing target line.

    python tools/runtime_witness.py targets/h03_dependencies --check ground_truth/h03.json
    APP_KEX=X25519 python tools/runtime_witness.py targets/h06_external_config --check ground_truth/h06.json

With --check: every ground-truth item marked runtime=executed must be witnessed on at least one of
its lines, items marked not-executed and decoys must not be, and constructor/factory calls on lines
that carry no ground-truth marker are reported as UNMAPPED (a missing ground-truth entry).
"""
from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
import types
from pathlib import Path

WATCHED = {"cryptography", "nacl", "jwt", "itsdangerous", "pyotp", "pqcrypto", "kyber_py", "dilithium_py",
           "oqs", "hashlib", "_hashlib", "hmac", "_blake2", "_md5", "_sha1", "_sha2", "_sha3"}
TOOL_ID = 3


_RESOLVED: dict[int, tuple] = {}


def _module_of(obj) -> str:
    mod = _declared_module(obj)
    if mod.split(".")[0] in WATCHED or not isinstance(obj, types.BuiltinFunctionType):
        return mod
    # Extension functions (Rust/C) may report a bare or empty module name: find the watched module exposing them.
    cached = _RESOLVED.get(id(obj))
    if cached and cached[0] is obj:
        return cached[1]
    name = getattr(obj, "__name__", None)
    for modname, module in list(sys.modules.items()):
        if module is not None and modname.split(".")[0] in WATCHED and getattr(module, name, None) is obj:
            mod = modname
            break
    _RESOLVED[id(obj)] = (obj, mod)
    return mod


def _declared_module(obj) -> str:
    if isinstance(obj, type):
        return obj.__module__ or ""
    mod = getattr(obj, "__module__", None)
    if mod:
        return mod
    owner = getattr(obj, "__self__", None)
    if owner is None:
        return ""
    if isinstance(owner, type(sys)):
        return owner.__name__
    if isinstance(owner, type):
        return owner.__module__ or ""
    return type(owner).__module__ or ""


def _kind(obj) -> str:
    """'factory' for classes, functions and class-bound methods; 'operation' for instance-bound methods."""
    if isinstance(obj, type):
        return "factory"
    owner = getattr(obj, "__self__", None)
    return "factory" if owner is None or isinstance(owner, (type, type(sys))) else "operation"


def _describe(obj) -> str:
    name = getattr(obj, "__qualname__", None) or getattr(obj, "__name__", None) or type(obj).__name__
    return f"{_module_of(obj)}.{name}"


class Witness:
    def __init__(self, target: Path):
        self.target = str(target)
        self.hits: dict[tuple[str, int], dict] = {}
        self._files: dict[str, str] = {}
        self._lines: dict = {}

    def _where(self, filename: str) -> str:
        kind = self._files.get(filename)
        if kind is None:
            if filename.startswith(self.target + os.sep):
                kind = "target"
            elif filename.startswith("<") and not filename.startswith("<frozen"):
                kind = "generated"
            else:
                kind = "library"
            self._files[filename] = kind
        return kind

    def _line(self, code, offset: int) -> int:
        table = self._lines.get(code)
        if table is None:
            table = self._lines[code] = [pos[0] for pos in code.co_positions()]
        index = offset // 2
        return table[index] if index < len(table) and table[index] else code.co_firstlineno

    def _record(self, filename: str, line: int, callee, via) -> None:
        key = (os.path.relpath(filename, self.target).replace(os.sep, "/"), line)
        entry = self.hits.setdefault(key, {"callees": set(), "kinds": set(), "via": set()})
        entry["callees"].add(_describe(callee))
        entry["kinds"].add(_kind(callee))
        if via:
            entry["via"].add(via)

    def on_call(self, code, offset, callee, _arg0):
        where = self._where(code.co_filename)
        if where == "library":
            return sys.monitoring.DISABLE
        if _module_of(callee).split(".")[0] not in WATCHED:
            return None
        if where == "target":
            self._record(code.co_filename, self._line(code, offset), callee, None)
            return None
        frame = sys._getframe(1)
        while frame is not None and self._where(frame.f_code.co_filename) != "target":
            frame = frame.f_back
        if frame is not None:
            self._record(frame.f_code.co_filename, frame.f_lineno, callee, code.co_filename)
        return None


def run_target(target: Path, argv: list[str]) -> Witness:
    witness, mon = Witness(target), sys.monitoring
    mon.use_tool_id(TOOL_ID, "pqc-benchmark-witness")
    mon.register_callback(TOOL_ID, mon.events.CALL, witness.on_call)
    sys.path.insert(0, str(target))
    cwd, saved_argv = os.getcwd(), sys.argv
    os.chdir(target)
    sys.argv = [str(target / "main.py"), *argv]
    mon.set_events(TOOL_ID, mon.events.CALL)
    try:
        runpy.run_path(str(target / "main.py"), run_name="__main__")
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise
    finally:
        mon.set_events(TOOL_ID, 0)
        mon.register_callback(TOOL_ID, mon.events.CALL, None)
        mon.free_tool_id(TOOL_ID)
        os.chdir(cwd)
        sys.argv = saved_argv
    return witness


def check(witness: Witness, ground_truth: Path) -> tuple[list[str], list[str]]:
    doc = json.loads(ground_truth.read_text())
    hit = set(witness.hits)
    problems, info, mapped = [], [], set()
    lines_of = {item["id"]: {(loc["file"], loc["line"]) for loc in item["locations"] if loc["file"].endswith(".py")}
                for item in doc["items"]}
    expected = set().union(*(lines_of[i["id"]] for i in doc["items"] if i["runtime"] in ("executed", "conditional")))
    for item in doc["items"]:
        lines = lines_of[item["id"]]
        mapped |= lines
        if item["runtime"] == "not-executed" or item["status"] == "decoy":
            lines = lines - expected  # lines shared with executing items prove nothing
        seen = bool(lines & hit)
        if item["runtime"] == "executed" and not seen:
            problems.append(f"NOT WITNESSED {item['id']}: expected to execute (lines {sorted(lines)})")
        elif item["runtime"] == "not-executed" and seen:
            problems.append(f"UNEXPECTED    {item['id']}: witnessed although marked not-executed")
        elif item["status"] == "decoy" and seen:
            problems.append(f"DECOY CALLS   {item['id']}: a decoy line calls into a cryptographic library")
        elif item["runtime"] == "conditional":
            info.append(f"conditional   {item['id']}: {'witnessed' if seen else 'not witnessed'} in this run")
    for (rel, line), entry in sorted(witness.hits.items()):
        if (rel, line) not in mapped and "factory" in entry["kinds"]:
            problems.append(f"UNMAPPED      {rel}:{line} calls {sorted(entry['callees'])}")
    return problems, info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", type=Path)
    parser.add_argument("--check", type=Path, help="ground_truth/hNN.json to validate against")
    parser.add_argument("--out", type=Path, help="write the witnessed call sites as JSON")
    parser.add_argument("--arg", action="append", default=[], help="extra command-line argument for main.py")
    args = parser.parse_args()
    target = args.target.resolve()
    witness = run_target(target, args.arg)
    report = [{"file": f, "line": n, "callees": sorted(e["callees"]), "kinds": sorted(e["kinds"]), "via": sorted(e["via"])}
              for (f, n), e in sorted(witness.hits.items())]
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[witness] {target.name}: {len(report)} target lines call into cryptographic libraries")
    if not args.check:
        return 0
    problems, info = check(witness, args.check)
    for line in info + problems:
        print("  " + line)
    print(f"[witness] check {args.check.name}: " + ("OK" if not problems else f"{len(problems)} problem(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
