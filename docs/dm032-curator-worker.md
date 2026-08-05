# DM-032 implementation record

DM-032 implements an evidence-only curator worker on the released DM-030 policy
and DM-031 resource-scoped queue. The generic manifest/task/proposal boundary is
provider-replaceable; V1 includes a fixed DeepSeek V4 Pro HTTP adapter and a
scripted provider used by all public tests.

The worker revalidates the live claim, ledger checkpoint and deterministic
policy plan on both sides of the provider call. It persists attempt count before
network, bounds request/response/tokens/cost, rejects reasoning and tools, stores
only a validated proposal plus minimum response evidence, and finishes the
queue item as `review-required`. It has no ledger signer or effect interface.

Registration is a closed binding of enabled state, implementation, exact
content-addressed profile and opaque secret handle. `DeepSeekProvider` conforms
to the replaceable `CuratorProvider` protocol; injected scripted transports use
the same invocation boundary in public tests. Retry exhaustion survives process
restart, and proposal, deferred and failed rows recover the corresponding
idempotent DM-031 completion after response loss.

The wheel exports `daimon-curator-worker` as an owner-only one-shot boundary.
It loads the real hosted runtime and coordinator under the state-root lock,
reads canonical profile/registration/task and exact content from protected
files, obtains both custody password and provider key from descriptors, and
prints only a validated proposal artifact or a stable diagnostic code. Public
schemas, a disabled placeholder registration and deterministic vectors are
checked in; conformance makes authority/disclosure and durable recovery
separate release requirements.

Provider facts were revalidated against DeepSeek's official docs on
2026-08-04: `deepseek-v4-pro` remains listed, Chat Completions and JSON Output
are available, legacy aliases are retired, and explicit `thinking.disabled` is
supported. V4-Pro remains preview according to the 2026-07-31 changelog, so a
future provider release requires a new hashed profile rather than silent reuse.

All checked-in evidence is synthetic. No provider credential, personal memory,
raw live prompt/response, endpoint override or billable CI call is included.
Provider readiness remains explicitly unproven until a protected deployment
supplies the opaque handle and records the opt-in redacted live receipt.
