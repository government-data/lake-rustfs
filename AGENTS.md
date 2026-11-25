# AGENTS.md

Instructions for coding agents working in this repository, the
`lake-rustfs` module of Quality Data. Adapted from `quality-sdk`'s
`AGENTS.md`: the same way of working, for this repository.

## What this is

`lake-rustfs` is an application module of Quality Data (quality-sdk
decision 0002): the lake on RustFS. It provides the capability `lake`
(S3, Iceberg REST, STS, the gate's mTLS and `lake-admin/1`).

- `crates/lake-rustfs-admin/`: the lake admin adapter, the service that
  serves `lake-admin/1` to the core with mTLS (core decision 0078).
- `Dockerfile`: the adapter's image.
- `module.yaml`: the module's manifest, its one version source.
- `compose.yml`: the services an installation runs, the images by digest
  from the signed index; `compose/` the entrypoints it mounts.
- `tools/verify/`: scripts that check external behaviour (Docker, RustFS),
  run alone, their containers `qs-verify-…` removed in a trap.
- `tools/package.sh`: the module's package, deterministic.
- `docs/`: internal documentation (decisions, implementation).
  **Ignored by git, never committed, pushed or published.**

## Before you change anything

1. **Find the decision.** The work here follows quality-sdk decision 0002
   and core decision 0078. Read the step you are doing and its check.
2. **Follow the decision; do not redesign it in code.** If the code needs
   something the decision does not say, stop and say so.
3. **Verify external behaviour first** (RustFS, Docker Compose) with a
   script before building on it, and record the result in the decision.

## Rules

- **The adapter keeps no data and no secret.** The keys it needs travel in
  each request's headers and are never logged, by either side. Logs carry
  the operation, the warehouse or pool, the status and the code.
- **It answers the core's server alone**, by the role of its certificate.
- **No personal data** in logs, test fixtures, examples or documentation.
- **Secrets** never go in the repository, a log or a commit.
- **Images by digest.** RustFS is the mirror in this module's ECR
  repository, never Docker Hub; `compose.yml` takes every image from the
  signed index (`IMAGE_*`).
- **The core is a git dependency pinned by a full commit SHA** until
  quality-sdk holds `contracts` and `module-testkit`. The pin moves only in
  a pull request of its own, whose CI runs the contract cases.
- **Never real cloud accounts in development or tests.** Releasing (a `v*`
  tag) is a person's.

## Language

**English only**: code, identifiers, comments, documentation, messages,
logs, commits, branches and pull requests. The only Spanish allowed is the
`es` text of the manifest's menu (text people read in the product).

## Size limits

- **Rust file** 400, hard 800 lines. **Function** 60, hard 100 lines
  (Clippy `too_many_lines`). **Test files** 800, no hard limit.
- **A change**: at most about 400 diff lines without generated files.

## Checks before a commit

```sh
cargo fmt --all -- --check
cargo clippy -p lake-rustfs-admin --all-targets --locked -- -D warnings
cargo test -p lake-rustfs-admin --locked
tools/package.sh "$(yq -r .version module.yaml)"
```

On a shared machine, build one crate at a time and never two builds at
once (see quality-sdk's `AGENTS.md`, "Builds on this machine").

## Do not

- Do not commit, quote or link a decision: code comments may name it by
  number ("core decision 0078"), never copy its content.
- Do not weaken a test, a lint or a check to make it pass.
- Do not push a tag: tagging publishes to AWS.
