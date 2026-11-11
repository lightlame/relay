# Contributing

## Setup

1. Install Rust stable (MSVC), Node.js 20+, Visual Studio Build Tools (C++ workload) and
   the Windows SDK.
2. Run:

```powershell
npm ci
npm --prefix frontend ci
npm run tauri dev
```

## Checks before a PR

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run check:web
```

Network integration tests are ignored by default:

```powershell
cargo test -p test_fixtures -- --ignored
```

## Code style

- Keep capture data immutable; edit only drafts.
- Mask secrets in any new UI or export surface.
- Prefer small focused modules in the appropriate crate.
- Do not add telemetry, remote fonts or cloud dependencies.
