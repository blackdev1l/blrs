# Known issues in the vendored BUD spec

The documents in this directory are vendored from
<https://github.com/hzrd149/blossom> **unmodified**. The defects below are in the
upstream text, not in this server. They are recorded here because they change
what a correct implementation must do.

## BUD-11: the worked authorization-token example is not self-consistent

`docs/buds/11.md` shows a kind-24242 token whose declared `id` does not match
its own contents. Three separate defects:

**1. The rendered event is missing a `server` tag.** The canonical NIP-01 digest
of the event exactly as shown is:

```
7346aee79b49f60327a9d052f4b61b08208407712f422605a2733237162c8cfd
```

but the document declares:

```
7a1735c3852cf3f374edae4b2af2ee18e750e6dec583e19c4795d3b179af6d17
```

Appending `["server","cdn.example.com"]` as the **final** tag reproduces the
declared id exactly, so the intended event is:

```
[0, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
 1772019044, 24242,
 [["t","upload"], ["expiration","1708858680"], ["x","b167…f553"], ["server","cdn.example.com"]],
 ""]
```

That is a 256-bit match, so it is not a coincidence.

**2. The `Authorization` header value is JSONC, not JSON.** Base64url-decoding
the header in the document yields a body containing a `//` comment, which a
strict JSON parser rejects.

**3. The decoded header misspells `pubkey` as `publkey`.** The value cannot be
parsed into a nostr event even if comments were tolerated.

### What this means for this server

`AuthToken::verify` recomputes the canonical NIP-01 id and verifies the
signature over the **recomputed** digest. It never trusts the declared `id`
field: doing so would let an attacker sign arbitrary digest bytes and claim
arbitrary content. A consequence is that the upstream example, as literally
rendered, is rejected with `BadEventId` — which is the correct behaviour.

The test vector in `crates/blossom-core/src/auth.rs` therefore uses the four-tag
reconstruction. Its expected id comes from the upstream document itself, so the
test still has an independent source of truth.

**4. The example's `content` violates BUD-11's own MUST.** BUD-11 says every
authorization token "MUST have the `content` set to a human readable string
explaining intended use to the user", but the worked example has
`"content": ""`. A server that enforced that MUST would reject the specification's
own example, so this server does not enforce it. Treating `content` as advisory
is the interoperable reading.

## Verification

Every claim above was reproduced independently rather than taken on trust: the
digests were recomputed with a standalone sha256 of the NIP-01 canonical array,
and the `publkey` misspelling and the `//` comment are visible in the
base64url-decoded header. See the test module in
`crates/blossom-core/src/auth.rs` for the four-tag vector.
