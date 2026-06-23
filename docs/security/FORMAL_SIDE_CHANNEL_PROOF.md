# Formal side-channel proof gate

This project now has an in-tree formal side-channel proof gate for source-level obligations.

The gate is intentionally precise about its boundary:

* source-level proof obligations are represented in `SSH_Lib.Crypto.Constant_Time_Proof`;
* the security test suite checks that every side-channel-sensitive primitive has a source-level proof status;
* the release tool `check_formal_side_channel_proof` verifies that the proof catalogue, manifest, tests, and regression scans are present;
* external leakage tooling, compiler/code-generation review, and independent cryptographic review remain required before making a mathematical constant-time claim.

## Source-level proof obligations

The following obligations are tracked for every primitive in `SSH_Lib.Crypto.Constant_Time_Assurance.Crypto_Primitive`:

* no secret-dependent branches;
* no secret-dependent loop bounds;
* constant-time selection for secret choices;
* constant-time equality for secret comparisons;
* fixed public-width arithmetic where applicable;
* invalid-ciphertext fallback selection for KEM decapsulation;
* source-audit tokens present.

## Non-goals

This gate does not prove the compiler preserved constant-time behaviour. It also does not replace dudect/ctgrind-style leakage testing, binary inspection, or independent cryptographic review.

A release may claim "source-level side-channel proof gate passed" only after the in-tree tools and tests pass. It may not claim "formally constant-time" until the external evidence listed in `tests/vectors/security/SIDE_CHANNEL_FORMAL_PROOF_MANIFEST.txt` exists and passes.
