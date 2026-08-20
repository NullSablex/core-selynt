# Build & Installation

## Build

!!! important
    The binary **must** be compiled with the `x86_64-unknown-linux-musl` target to produce a static executable with no dependency on the host's glibc. Building without this target produces a binary that is incompatible with DirectAdmin servers using different glibc versions.

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting binary will be at `target/x86_64-unknown-linux-musl/release/core-selynt`.

The `release` profile is already configured in `Cargo.toml` with `strip`, `lto`, `opt-level = "z"`, `codegen-units = 1` and `panic = "abort"`.

## Installation

The binary must be installed in the plugin directory with the setuid bit:

```bash
install -o root -g root -m 4755 target/x86_64-unknown-linux-musl/release/core-selynt \
    /usr/local/directadmin/plugins/selynt_panel/bin/core-selynt
```

Verify:

```
-rwsr-xr-x 1 root root ... core-selynt
```
