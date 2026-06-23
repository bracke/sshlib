# ML-KEM encapDecap FIPS203 ACVP vectors

Place official ACVP files here:

- `prompt.json`
- `expectedResults.json`

The `test_pq_external_kats` executable parses the ACVP JSON shape for `ML-KEM / encapDecap / FIPS203`, filters `parameterSet = "ML-KEM-768"`, executes encapsulation and decapsulation cases, and compares `c` and `k` against `expectedResults.json`.
