# OAuth2

<a href="https://crates.io/crates/oauth2"><img src="https://img.shields.io/crates/v/oauth2.svg"></a>
[![Build Status](https://github.com/ramosbugs/oauth2-rs/actions/workflows/main.yml/badge.svg)](https://github.com/ramosbugs/oauth2-rs/actions/workflows/main.yml)

An extensible, strongly-typed implementation of OAuth2
([RFC 6749](https://tools.ietf.org/html/rfc6749)).

Documentation is available on [docs.rs](https://docs.rs/oauth2). Release notes are available on [GitHub](https://github.com/ramosbugs/oauth2-rs/releases).

For authentication (e.g., single sign-on or social login) purposes, consider using the
[`openidconnect`](https://github.com/ramosbugs/openidconnect-rs) crate, which is built on top of
this one.

## Minimum Supported Rust Version (MSRV)

The MSRV for the current development version of this crate is Rust **1.85**.

The MSRV for *5.1.y* releases of this crate is Rust **1.71**.

The MSRV for *5.0.y* releases of this crate is Rust **1.65**.

The MSRV for *4.x* releases of this crate is Rust 1.45.

Beginning with the 5.0.0 release, this crate will maintain a policy of supporting
Rust releases going back at least 6 months. Changes that break compatibility with Rust releases
older than 6 months will no longer be considered SemVer breaking changes and will not result in a
new major version number for this crate. MSRV changes will coincide with minor version updates
and will not happen in patch releases.

## Dependency security

The Rust 1.85 CI lockfile has been refreshed to patched TLS, certificate-verification, and
HTTP-client dependencies. Applications using this library must update their own lockfiles
(`cargo update`) to receive transitive dependency fixes; this repository's lockfile does not
constrain downstream applications.

CI audits both a fresh dependency resolution and `Cargo-1.85.lock` against RustSec, without
advisory suppressions. Dependabot checks Cargo dependencies and GitHub Actions weekly, but
does not refresh the nonstandard MSRV lockfile. To refresh it while preserving Rust 1.85:

```sh
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +1.85.0 update
cp Cargo.lock Cargo-1.85.lock
cargo audit --file Cargo-1.85.lock
cargo +1.85.0 test --workspace --all-features --locked
```

The SHA-256/HMAC dependencies remain on their compatible release lines: `sha2` 0.11.1
requires Rust 1.88, above this project's MSRV. Reqwest-based async examples now declare
their required feature so no-default-feature builds skip unavailable HTTP clients.

Security-sensitive behavior:

- On native targets, `oauth2-reqwest`'s default clients disable redirects. Clients supplied
  through `From` retain the caller's policy. On WebAssembly, redirects are browser-controlled.
- Applications supplying HTTP clients must disable redirects to prevent SSRF and credential
  disclosure. See the [HTTP client upgrade guidance](UPGRADE.md#use-stateful-http-clients).
- Token parse-error `Debug` output redacts response bodies and value-bearing parser errors.
  The `RequestTokenError::Parse` fields still permit explicit inspection; do not log those
  raw fields when responses may contain credentials.
- The ureq adapter preserves HTTP error responses for OAuth error parsing, including
  device-flow polling errors, instead of treating HTTP status codes as transport failures.
