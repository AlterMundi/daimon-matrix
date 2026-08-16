# Daimon Cluster adaptation for the Matrix source runtime

DM-081 adds no source semantics or authority to `daimon-cluster`. Cluster hosts
the installed Matrix process and its owner-local files; Matrix alone verifies
source identity, signatures, evidence, disclosure, quarantine and promotion.

For runtime bundle V7, the host adapter must:

- preserve one private Matrix state volume per embodiment;
- include the local ledger, source CAS, intake lock/journal and each configured
  foreign-being ledger in the same quiesced backup/restore boundary;
- keep files owner-only, reject symlinks and never share a writable SQLite file
  between embodiments;
- supply exact root/current authority artifacts for every `known_beings` entry;
- treat CAS and known-ledger filenames as relative private state names and
  reject collision with ledger, keystore, socket or other runtime files;
- restart the same bytes after an ambiguous process failure and let Matrix's
  journal determine whether a source operation completed; and
- continue providing body snapshots and resource-fence/effect-truth evidence
  only for actual hosted resources or projection effects.

Cluster must not inspect or reinterpret source claims, select a fork winner,
auto-admit content, mint assessments/import decisions, infer a disclosure grant
from process placement, fetch a source URI, copy another being's database, or
turn successful lifecycle/effect evidence into source truth.

DM-082 defines the relationship/grant verifier injected into Matrix's
disclosure boundary and proves it with an isolated recipient-intake journey.
DM-071 will add the consented external canary. Until that live evidence lands,
external source disclosure remains disabled even when peer transport, `/we`,
Tribe or Cluster reachability succeeds.

The future Cluster acceptance should install the exact released Matrix wheel,
start two independently hosted beings, preserve V7 state across restart and
backup/restore, and compare the resulting Matrix report/receipts. It must not
reimplement the protocol in Cluster.
