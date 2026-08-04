# DM-022 Cluster compatibility receipt

Checked 2026-08-04 against `nicoechaniz/daimon-cluster` reconciled main
`54a30faf06be7af4995afed0a0ce98ea273d1adf`.

Cluster's executable compatibility fixture and Matrix's published provisional
fixture contain byte-identical manifest and event files:

| file | SHA-256 |
|---|---|
| `manifest.json` | `eacb48327b56e440a0daf1a8f07bc1f6066917a191a9dd5d85061a9204145864` |
| `configuration-proposal.json` | `61bcacbb6a0a3ece863cbc5f1ef80e9cc57ae61f83c0cd6611f2980ec1150d3a` |

Cluster test `tests/test_weave.py::test_accepts_daimon_matrix_golden_vector`
validates those bytes with real Ed25519 verification. Matrix DM-022 validates
the same files through `ProvisionalAuthority`, then separately publishes and
regenerates root-bound vectors under `vectors/weave/v1/root-bound/`.

The complete Cluster `tests/test_weave.py` lane was rerun at that commit:
`7 passed`.

This receipt proves the wire seam, not completion of the Cluster host adapter.
The remaining downstream work is specified in
[`docs/dm022-cluster-adaptation.md`](../dm022-cluster-adaptation.md).
