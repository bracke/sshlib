# Phase 19 Initial-Context Compliance

This document maps the current Phase 19 tree back to the implementation context supplied at the start of this chat.

## Covered by concrete artifacts

- Security review packages: `SSH_Lib.Security_Audit`, `SSH_Lib.Diagnostics.Redaction`, and `SSH_Lib.Protocol.Negative_Tests`.
- Security fixture families: host-key verification, algorithm negotiation, protected packet/MAC behavior, authentication ordering and malformed auth inputs, Git command quoting, config-as-data behavior, binary byte preservation, timeout/dirty-state behavior, resource bounds, exception containment, hostile transcripts, live channel protected-boundary behavior, deterministic Fuzz_Lite, and version-adapter consumption.
- Security tools: `check_security`, `check_no_subprocess`, `check_binary_paths`, `check_sensitive_logging`, and `check_phase19_context`.
- Required documentation: `docs/SECURITY_REVIEW.md`, `docs/THREAT_MODEL.md`, `docs/TESTING.md`, and `docs/VERSION_INTEGRATION.md`.
- Release path: integrated tests, split security tests, version integration tests, deterministic examples, tools build, release guards, audit self-tests, and final audit scans.

## Live-runtime boundary

The Phase 19 context requires `Sessions.Open` to return `Ok` only for connected, encrypted, host-verified, user-authenticated sessions. The current tree has explicit success-state guards and hostile transcript fixtures. It must continue to fail closed for live server paths that cannot prove every gate.

This means the documentation now distinguishes between fixture-backed security coverage and remaining live backend completion work. A green Phase 19 fixture run is not a substitute for real Alire/GPR/GNAT release verification.

## Guard

`tools/check_phase19_context.adb` enforces this mapping. It fails if required packages, tests, documentation sections, release commands, or the explicit live-runtime fail-closed statement disappear.
