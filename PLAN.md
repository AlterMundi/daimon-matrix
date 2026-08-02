# Daimon Matrix delivery plan

## Product boundary

The first operational release is a coordinated Cluster + Weave + Tribe
release. Matrix provides the normative ontology, schemas, vectors, and future
root binding but no required daemon.

## Delivery sequence

1. Freeze ontology, lifecycle identifiers, the being manifest, `dm.we.v1`,
   Tribe membership, and resource-fence semantics.
2. Publish shared schemas and positive/negative conformance vectors.
3. Replace identity-wide leases in Cluster with resource-scoped fences and an
   embodiment/incarnation registry.
4. Add the isolated Cluster `weave` service: ledger, heads, preview, pull,
   diff, decisions, projections, and `/we` fan-out.
5. Extend Tribe Bridge with generic typed encrypted payloads and founded-tribe
   membership artifacts.
6. Integrate HMK memory and one external-identity configuration adapter.
7. Run the Legion/daimonmatrix acceptance journey and publish receipts.
8. Later implement Matrix root custody, embodiment credentials, recovery, and
   explicit binding of provisional history.

## Release invariants

- Multiple embodiments of one being can be awake.
- Every event and response retains origin.
- Preview is read-only; pull is idempotent; pull does not adopt.
- Decisions are local and reversible through successor events.
- Secret values never enter synchronized bytes.
- High-impact projections require a human confirmation.
- Resource fences reject stale writers only for the exact resource.
- No shared writable database is copied between embodiments.

## Completion evidence

Completion requires green conformance and unit suites in all three
repositories plus a two-host run proving simultaneous presence, paginated
sync, navigable differences, independent adoption, reversal, fan-out,
restart-resume, and resource-fence rejection. CI and self-audit are the review
gate; no recursive review ceremony is required.
