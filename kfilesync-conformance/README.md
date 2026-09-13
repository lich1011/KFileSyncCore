# kfilesync-conformance

Shared **conformance fixtures** for both the Rust core and the Kotlin/Swift
mobile bindings. The same JSON inputs are fed through both runners; if the
outputs diverge, the relevant CI job fails.

## Layout

```
fixtures/
├── chunking/                 ← Sprint 1
│   └── threshold_boundaries.json
├── version_vector/           ← Sprint 1
│   ├── ancestor_basic.json
│   └── merge_concurrent.json
├── nonce_window/             ← Sprint 2 (done, wired into rust-runner; no Kotlin runner yet)
│   └── verify_and_record.json
├── conflict_resolver/        ← Sprint 2 (done, wired into rust-runner; no Kotlin runner yet)
│   ├── copy_name.json
│   └── apply_resolution.json
├── sync_plan/                ← Sprint 3 (done, wired into rust-runner; no Kotlin runner yet)
│   └── tombstone_propagation.json
├── wire/                     ← Sprint 4 (done, wired into rust-runner; no Kotlin runner yet)
│   ├── discovery.json
│   ├── pairing.json
│   ├── share.json
│   ├── sync_index.json
│   └── transfer.json
├── ignore_spec/              ← Sprint 6 (done, wired into rust-runner; no Kotlin runner yet)
│   └── matching.json
└── trust/                    ← Sprint 5 (done, wired into rust-runner; no Kotlin runner yet)
└── evaluate_inbound.json

rust-runner/                  ← `cargo run -p kfilesync-conformance-runner`
```

The Kotlin runner lives in the [`KFileSyncMobile`](https://github.com/kfilesync/KFileSyncMobile)
project under `sharedLogic/src/commonTest/.../ConformanceTest.kt`.

## Fixture format

Each fixture is a JSON object whose schema depends on the subject under
test. The common pattern:

```json
{
  "name": "human readable test name",
  "description": "optional",
  "cases": [
    { /* input */, "expected_X": ... }
  ]
}

```

When adding a new fixture:

1. Pick a directory matching the module (e.g. `nonce_window/`)
2. Use a descriptive filename (e.g. `replay_after_window_expires.json`)
3. Add a deserializer + assertion in both `rust-runner/` and the Kotlin runner

See `CORE_DEVELOPMENT_PLAN.md` §2 for the full sprint-by-sprint coverage plan.

