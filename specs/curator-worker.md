# Evidence-only curator worker

Status: normative for `dm.curator-worker.* /v1` and DM-032.

## Authority

The worker is a replaceable DM-018 `curator-worker` adapter. It may transform
one policy-authorized DM-031 queue item into one inert proposal. It cannot sign
as `/me`, append Matrix, execute DM-030, approve DM-033 review, publish, call
tools, follow URLs, acquire a Cluster fence, or treat provider output as fact.
Every manifest authority flag is false.

The task binds the exact DM-031 item and current generation claim, DM-030
policy/candidate/checkpoint/transition plan, provider profile, prompt and output
schema. The item must be owner-local `queue-item` work of kind
`memory-evaluation|memory-proposal`; its input reference and SHA-256 must name
the exact candidate. The plan must recompute byte-identically and have outcome
`eligible|review-required`. Any other outcome refuses before disclosure.

## Provider boundary

The only V1 production profile is the exact HTTPS origin
`https://api.deepseek.com`, path `/chat/completions`, model
`deepseek-v4-pro`, OpenAI Chat Completions, JSON Output, non-streaming and
explicit non-thinking mode. No legacy alias, redirect, proxy environment,
dynamic import, arbitrary URL, tool/function call, or reasoning content is
accepted. As verified on 2026-08-04, the model ID is available but DeepSeek
still describes V4-Pro as preview pending a later official release. Therefore
model availability, pricing and backend fingerprint are evidence, never stable
authority.

The content-addressed profile records the exact prompt/output schema hashes,
secret handle, limits, and worst-case cache-miss/output tariff snapshot. A
provider change creates another profile. A closed
`dm.curator-worker.registration/v1` separately binds `enabled`, the allowlisted
implementation, exact profile ID/hash and the same opaque secret handle. There
is no module, class, URL, template or expression field. A disabled registration
refuses before secret resolution or network. The key is resolved just in time
into a mutable buffer, is absent from body/config/log/artifacts, and is
overwritten best-effort after the call; Python memory zeroization is not
claimed.

Matrix resolves the candidate's content reference, verifies exact bytes and
hash, serializes one canonical JSON evidence object, then scans the final body.
Private/protected content is never sent. Personal content additionally requires
explicit granted consent. Evidence is a JSON string under an inert data field,
so delimiters cannot create another message or role.

## Validation and retry

Immediately before disclosure and after response, Matrix requires the same
claim/generation, unexpired half-open lease/deadline, exact live ledger
checkpoint and byte-identical DM-030 plan. Drift is stale work, not a provider
success.

Responses have bounded bytes, UTF-8, duplicate-free I-JSON, depth/node limits,
one choice, exact model, `stop`, assistant JSON content, zero reasoning tokens,
no tool shape, bounded usage and cost. The local closed proposal schema is the
authority; provider JSON mode is only a transport aid. Category, derivation and
evidence references cannot be substituted by the model.

The durable attempt row is committed before each call. Transient retries are
bounded across restart, not merely within one process. Provider response loss
may duplicate computation but cannot create two accepted proposals. Proposal
bytes and their content are committed before DM-031 completion; retry completes
the same `proposed` result. Different bytes conflict. No model output creates a
canonical memory event.

An exhausted retryable attempt is durably `deferred`; a non-retryable provider,
schema, disclosure or content failure is durably `failed`. That terminal row is
committed before the matching DM-031 completion. A process lost between those
commits resumes the same outcome without another provider call. A transient
error code is retained while the row is still `requested`, so a restarted
process cannot reset the attempt budget or silently reclassify exhaustion.

## Proposal

`dm.curator-worker.proposal/v1` is content-addressed and retains task/attempt/
claim, exact provider request hash, provider/profile/model/prompt/schema,
content reference, proposed operation, category/derivation, evidence and
contradiction references, classification suggestion, qualitative confidence,
uncertainty/warnings, response hash/ID/fingerprint/usage/cost and production
time. Its authority is always `evidence-only`.

All successful worker output completes DM-031 as `proposed`, even when DM-030
found the input automatically eligible. DM-033 must make a separate
purpose-limited human decision before any proposal can become canonical.

## Deployment

The installed `daimon-curator-worker` command is a one-shot owner-local process.
It acquires the Matrix state-root writer lock, loads the same verified runtime
and DM-031 coordinator, accepts only owner-only basename artifacts, and uses
the fixed `DeepSeekHTTPS` transport. Runtime custody password and provider key
enter only through distinct inherited descriptors; neither has an argv or
environment fallback. Output is the validated proposal artifact, whose
statement remains an immutable local content reference rather than terminal
text.

Public CI uses only a scripted provider and synthetic content. A live smoke is
opt-in, uses a synthetic task and protected deployment configuration, and may
retain only redacted hashes/usage/status. Absence of a protected secret handle
means live readiness is unproven; it never weakens the synthetic contract or
enables an environment-variable fallback.
