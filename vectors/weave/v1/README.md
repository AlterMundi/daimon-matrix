# `dm.we.v1` golden vectors

All JSON fixtures are byte-canonical. The Ed25519 key is deterministic public
test material (`0x01` repeated 32 times as the private seed) and must never be
used outside conformance tests.

The valid event proves manifest hashing, origin binding, secret-slot
references without secret values, canonical content hashing, domain-separated
signing, and a configuration proposal that remains non-effective until a
local decision.

