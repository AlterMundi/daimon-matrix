# Canonical artifacts

Status: normative common rules.

All protocol JSON uses UTF-8, duplicate-free object names, I-JSON integers,
Unicode scalar strings, and RFC 8785 JSON Canonicalization Scheme. Identifiers
and signatures are computed over domain-separated canonical bytes. Unknown
fields fail closed in closed V1 objects.

## Artifact families

- `dm.identity.artifact/v1`: being genesis/control, plural embodiment and
  incarnation authorization, provisional-history binding, and activation.
- `dm.keystore/v1`: authenticated encrypted custody container; never a
  synchronized artifact.
- `being-manifest/v1`: provisional administrator configuration.
- `being-manifest/v2`: root-bound configured-origin view whose members cite
  exact DM-021 credential and incarnation artifacts.
- `dm.we.v1`: origin-retaining durable event.
- `dm.we.heads/v1` and `dm.we.delta/v1`: bounded synchronization exchange.
- `dm.we.sync-request/v1` and `dm.we.sync-receipt/v1`: durable request and
  receiver-authored completion evidence.
- `dm.we.projection/v1`: deterministic disposable local decision view.
- `dm.we.request/v1` and `dm.we.response/v1`: live fan-out.
- `resource-fence/v1`: Cluster lease for one concrete resource.
- `tribe-*/v1`: declaration, invitation, acceptance, membership change,
  founder transfer, and resource grant artifacts.

## Event rules

Event IDs are UUIDs and do not substitute for the content hash. Each
incarnation has a monotonic sequence and predecessor chain. Additional causal
parents are sorted and unique. Valid branches from different origins coexist;
different bytes at one origin sequence quarantine that origin.

Signatures use Ed25519 and identify a currently authorized principal key.
Transport verification does not replace durable event verification. The
provisional principal signature authenticates origin but does not establish a
Matrix being root.

## Bounds

One event is at most 256 KiB canonical JSON. A delta page has at most 256
events and 1 MiB plaintext. Causal parents are capped at 64. Implementations
reject over-bound objects before allocation or persistence where practical.

## Projection and effect receipts

Receipts bind event, decision, adapter, exact preview/intent hash, actor,
resource fence if any, start/end time, result, and observed postcondition.
They contain no secrets. A new observation that contradicts the postcondition
requires reconciliation or a successor receipt; an earlier success is not
eternal effect truth.
