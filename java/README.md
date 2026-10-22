# Java PQC CBOM Benchmark (H0–H9)

This is a separate Java-language counterpart to the existing Python benchmark. The original Python targets and ground truth are untouched. Each tool must be given the same `targets/hNN_*` Java folder for a given hypothesis.

## Hypotheses
- H0: direct-use baseline
- H1: reflection/dynamic construction as Java analogues for Python metaprogramming
- H2: factories, wrappers, and indirection
- H3: third-party dependency usage (Bouncy Castle provider)
- H4: mixed classical, PQC, and hybrid identifiers
- H5: misleading names versus neutral names and label-only decoys
- H6: system properties/environment-driven algorithm selection
- H7: increasing call depth
- H8: policy-discriminating algorithms and compositions
- H9: evidence strength, indirect values, conditional paths, and decoys

## Fairness rules
1. Use the exact same Java source files for CBOMKit, CryptoBOM-Forge, and cdxgen. Do not create tool-specific source variants.
2. Keep ground-truth markers (`GT:`) fixed and separate from scanner findings.
3. Record tool version, scan command, exit status, output format, and warnings for each run.
4. Separate scan failure, unsupported-language/API behavior, missed detections, false positives, and incorrect algorithm/property identification. Do not automatically count unsupported algorithms as ordinary false negatives.
5. Compare algorithm identity, properties, and source evidence separately.

## Compatibility caveat
The source repository's existing documentation describes CBOMKit support in terms of Python `pyca/cryptography` and does not establish Java support. This Java corpus intentionally does not change language per tool. First run a small capability check with a direct Java JCA call; if a tool cannot analyze Java, report that result as a compatibility limitation and do not substitute Python inputs. CryptoBOM-Forge may depend on CodeQL findings, so Java support also depends on the relevant CodeQL Java query/database pipeline.

## Scope limitations in this first draft
This is a first-pass Java corpus, not a validated drop-in replacement for the existing benchmark. Some PQC entries are algorithm identifier strings rather than executable provider calls; those cases test string recognition and must be distinguished from actual cryptographic API use. Ground-truth counts and scoring rules need review before reporting precision/recall. H7 currently supplies a representative deep call chain rather than the full original depth/track matrix.

## Run guidance
Scan each `targets/hNN_*` directory separately. Do not execute application code merely to perform static analysis. The Java code is a static-analysis corpus and is not intended as a production cryptographic implementation.
