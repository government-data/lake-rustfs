# lake-rustfs

The lake of Quality Data on [RustFS](https://github.com/rustfs/rustfs), as
the `lake-rustfs` module: it provides the capability `lake` (S3, Iceberg
REST, STS, the gate's mTLS and `lake-admin/1`) to the modules that require
it.

## Layout

- `crates/lake-rustfs-admin/`: the lake admin adapter. It serves
  `lake-admin/1` (a lake's health, its warehouses and their replication)
  to the core's server alone, with mTLS of the installation's CA both
  ways, and keeps no data or secret of its own.
- `Dockerfile`: the adapter's image (distroless, non-root, port 9020).
- `module.yaml`: the module's manifest for quality-sdk, and its one version
  source.
- `compose.yml`: what an installation runs, the images by digest from the
  signed index (`IMAGE_RUSTFS`, `IMAGE_ADMIN`).
- `tools/package.sh`: the module's package, `lake-rustfs-<version>.tar.gz`,
  the same bytes for the same commit.

## Build

Requires Rust 1.90 or newer.

```sh
cargo fmt --all -- --check
cargo clippy -p lake-rustfs-admin --all-targets --locked -- -D warnings
cargo test -p lake-rustfs-admin --locked
docker build -t lake-rustfs-admin .
tools/package.sh "$(yq -r .version module.yaml)"   # writes dist/
```

## Release

A tag `v<version>`, equal to `module.yaml`'s `version`, pushes the
adapter's image to `quality-data/lake-rustfs/admin:<version>` in ECR and
prints its digest; if that version is already there it pushes nothing. The
package is built, kept as the run's artifact and its SHA-256 printed. RustFS
itself is not built here: it is the mirrored image in
`quality-data/lake-rustfs/rustfs`, pinned by digest.

## License

MIT.
