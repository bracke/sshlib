# ML-KEM keyGen FIPS203 ACVP vectors

Place official ACVP files here:

- `prompt.json`
- `expectedResults.json`

The `test_pq_external_kats` executable parses the ACVP JSON shape for `ML-KEM / keyGen / FIPS203`, filters `parameterSet = "ML-KEM-768"`, executes deterministic key generation from `d || z`, and compares the generated `ek` and `dk` against `expectedResults.json`.
