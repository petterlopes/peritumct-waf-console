# Toolchain

## Rust

| Pin | Value |
|-----|--------|
| **Stable release** | **1.98.1** (2026-09-03) |
| **MSRV** (`rust-version` in `Cargo.toml`) | `1.98.1` |
| **Docker builder** | `rust:1.98.1-bookworm` |
| **CI** | `dtolnay/rust-toolchain` with `toolchain: 1.98.1` |

Why 1.98.1: patch release that fixes a rustc **vtable miscompilation** in 1.98.0
(null function pointer in trait object vtables → UB). Production images and CI
must not stay on 1.98.0.

Announce: https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/

## Release profile (production)

`[profile.release]` in `rust/Cargo.toml`:

- `lto = true`
- `codegen-units = 1`
- `opt-level = 3`
- `strip = "symbols"`
- `panic = "abort"`

Dockerfile `RUSTFLAGS` sets opt-level / codegen-units / strip only.
**Do not** put `-C lto=…` in global `RUSTFLAGS` — it conflicts with dependency
builds that use `-C embed-bitcode=no`.

## License

Console sources: **GPL-3.0-or-later** (Linux-like copyleft). See [NOTICE](../NOTICE).
CrowdSec engine (separate process): MIT.
