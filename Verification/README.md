# Lean 4 verification model

This directory is an executable Lean 4 model of the security- and
interoperability-critical decision logic reviewed in this repository. Run it
with:

```sh
cd Verification
lake build
```

## Proven properties

| Model | Proven invariant | Swift correspondence |
| --- | --- | --- |
| `isSuccessStatus` | Only status codes in `[200, 300)` are successful, including `204`. | `Sources/Networking/Fetcher.swift`, `RawDataFetcher.swift`, and `Poster.swift` |
| `canonicalHTU` | The DPoP target has no query or fragment and retains scheme, authority, and path. | `Sources/DPoP/DPoPConstructor.swift` (PR #7) |
| `publicJWKParameters` | Private JWK parameters `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, and `k` cannot occur in an emitted header. | `Sources/Extensions/JWK+Extensions.swift`, `DPoPConstructor.swift`, and `BindingKey.swift` (PR #7) |
| `validCredentialResponse` | A valid response cannot contain both an immediate credential and a deferred transaction ID; errors are exclusive. | `Sources/Entities/Issuance/SingleIssuanceSuccessResponse.swift` and response decoding (PR #6) |
| `applyRefresh` | Refresh keeps the token binding type, preserves an omitted refresh token, rotates a supplied token, and takes nonce/expiry from the response. | `Sources/Main/Authorisers/AuthorizationServerClient.swift` (PR #5) |

## Scope boundary

These are proofs of a Lean reference model, not a compiler-checked refinement
proof from Swift source to Lean. Swift does not expose a verified semantics in
this repository. The model is intentionally small, executable, and mapped to
the relevant production functions so that changes to those functions require
reviewing the matching theorem.

Cryptographic primitives, URL parsing, JOSESwift serialization, HTTP I/O, and
remote issuer behavior remain trusted components. A source-level verification
would require a formally specified Swift subset or a verified translation layer.
