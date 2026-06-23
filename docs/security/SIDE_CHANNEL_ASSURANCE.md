# Side-channel assurance framework

This project now has an explicit side-channel assurance gate for the native
cryptographic code used by SSH_Lib.

The in-tree gate consists of:

- `SSH_Lib.Crypto.Constant_Time_Assurance`, a machine-readable catalogue of
  side-channel-sensitive primitives and their current assurance status.
- `tests/security/test_side_channel_assurance.adb`, which fails if any covered
  primitive is unassessed or removed from the assurance gate.
- `tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt`, which records
  the source files, expected implementation discipline, and forbidden
  regressions for each primitive family.

## Current status

The codebase has practical source-level hardening for RSA, ECDSA P-256,
Ed25519, X25519, finite-field Diffie-Hellman, ML-KEM-768 decapsulation,
SNTRUP761 decapsulation, UMAC, and SSH packet MAC verification. The gate is
intended to prevent silent regression from fixed-iteration / candidate-select
patterns back to secret-dependent branch, loop-bound, or early-return patterns.

## Boundary

This is a formal source/evidence gate, not an independent mathematical proof of
constant-time execution. A release that claims cryptographic constant-time
behavior still requires external leakage tooling, compiler/code-generation
inspection, official KAT execution, and independent crypto review.

## Release requirement

Before enabling new cryptographic algorithms by default, release validation must
run:

```text
alr exec -- gprbuild -P tests/security/security_tests.gpr
../ssh_lib_build/bin/tests_security/test_side_channel_assurance
```

The release checklist must also review the manifest entries for any primitive
whose source file changed since the previous release.


Side-channel assurance audit tool:

```text
../ssh_lib_build/bin/tools/check_side_channel_assurance
```
