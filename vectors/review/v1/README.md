# DM-033 human-review vectors

These are deterministic synthetic artifacts for the purpose-limited human
review boundary. `index.json` names each artifact and pins the SHA-256 of its
canonical JSON bytes.

The positive set contains single-reviewer and 2-of-2 accepted authorizations,
their exact requests, all four decision actions, matching accept/edit/reject
execution receipts, a short-lived access proof and revocation. The negative
decision changes signed content without deriving a new ID/signature and must
fail.

All identities, keys, memory references and times are public fixtures. Never
reuse their seed material or treat the vectors as deployment authorization.

Regenerate and compare exactly:

```text
python tools/generate_dm033_vectors.py --out /tmp/dm033-vectors
diff -ru vectors/review/v1 /tmp/dm033-vectors
```
