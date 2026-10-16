#!/usr/bin/env python3
"""Hygiene check for the benchmark targets.

Algorithm names must not leak into comments, docstrings, string literals or user-chosen identifiers,
because some scanners match raw text (cryptobom-forge applies a regex to the code snippet around each
CodeQL result; cdxgen substring-matches algorithm names in data-flow code).  A leak would let a tool
"detect" an asset for the wrong reason.  Lines that carry a GT marker are exempt: the text there is
intentional evidence or a deliberate decoy.

    python tools/check_hygiene.py
"""
from __future__ import annotations

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "targets"
MARKER = re.compile(r"GT:[A-Za-z0-9]")
WORDS = re.compile(
    r"(?i)(?<![a-z])(rsa|dsa|ecdsa|ecdh|eddsa|ed25519|ed448|x25519|x448|curve25519|aes|3?des|sha|sha[0-9_]+|md5|hmac|hkdf|"
    r"pbkdf2?|kyber|dilithium|ml[-_]?kem|ml[-_]?dsa|slh[-_]?dsa|sphincs|falcon|chacha(?:20)?|poly1305|x?salsa20|"
    r"secp[0-9a-z]+|brainpool[0-9a-z]*|pss|oaep|pkcs[0-9]*|gcm|cbc|ctr|ecb|ccm|siv|fernet|blake2[bs]?|sm3|sm4|camellia|"
    r"a?rc4|blowfish|shake(?:128|256)?)(?![a-z])")
# Tokens from cryptobom-forge's algorithm list; it matches them anywhere, case-insensitively.
SUBSTRINGS = ("AES", "ARC4", "BLAKE2", "BRAINPOOL", "CAMELLIA", "CAST5", "CHACHA20", "DES3", "DESEDE", "DH",
              "DIFFIEHELLMAN", "DSA", "FERNET", "HKDF", "IDEA", "MD5", "PBKDF2", "PSS", "RSA", "SCRYPT", "SECP",
              "SECT", "SEED", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHAKE", "SM3", "SM4", "TRIPLEDES")


def candidates(src: str):
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            yield tok.start[0], tok.start[0], "comment", tok.string
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.end_lineno, "string", node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.lineno, node.lineno, "identifier", node.name
        elif isinstance(node, ast.arg):
            yield node.lineno, node.lineno, "identifier", node.arg
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            yield node.lineno, node.lineno, "identifier", node.id
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            yield node.lineno, node.lineno, "identifier", node.attr
        elif isinstance(node, ast.alias) and node.asname:
            yield node.lineno, node.lineno, "identifier", node.asname


def main() -> int:
    findings = 0
    for path in sorted(ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        src = path.read_text()
        exempt = {n for n, line in enumerate(src.splitlines(), 1) if MARKER.search(line)}
        for first, last, kind, text in candidates(src):
            if any(n in exempt for n in range(first, last + 1)):
                continue
            hits = sorted({m.group(1).lower() for m in WORDS.finditer(text)} | {s for s in SUBSTRINGS if s in text.upper()})
            if hits:
                findings += 1
                print(f"{path.relative_to(ROOT.parent)}:{first}: {kind} {text[:60]!r} -> {', '.join(hits)}")
    print(f"[hygiene] {findings} leak(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
