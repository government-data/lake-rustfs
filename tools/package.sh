#!/usr/bin/env bash
# The module's package for quality-sdk, made the way the core makes its own:
#
#   tools/package.sh VERSION        # VERSION must be module.yaml's
#
# writes lake-rustfs-VERSION.tar.gz (in OUT_DIR, default dist/) with, at its
# root, module.yaml and compose.yml, and the entrypoints compose.yml mounts
# (compose/).
#
# The files are taken from the commit (HEAD), never the working tree, so
# nothing local (.env, keys) can come in. Regular files and directories only,
# as quality-sdk's package reader accepts; owner root, the commit's time,
# sorted, gzip without a name or time: the same commit makes the same bytes,
# which the signed index pins by SHA-256.
set -euo pipefail
export LC_ALL=C
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

files=(module.yaml compose.yml compose/rustfs-drives.sh compose/rustfs-tls.sh compose/lake-gate.sh)

version="${1:-}"
want="$(git show HEAD:module.yaml | sed -n 's/^version: *\([^ #]*\).*$/\1/p')"
if [[ -z "$version" ]]; then
  echo "usage: tools/package.sh VERSION (module.yaml has $want)" >&2
  exit 2
fi
if [[ "$version" != "$want" ]]; then
  echo "VERSION $version is not module.yaml's ($want)" >&2
  exit 2
fi

out="${OUT_DIR:-dist}"
mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf -- "${stage:?}"' EXIT
git archive --format=tar HEAD -- "${files[@]}" | tar -x -C "$stage"

# The package's modes, not this machine's umask.
chmod -R u=rwX,go=rX "$stage"

bad="$(find "$stage" ! -type f ! -type d)"
if [[ -n "$bad" ]]; then
  echo "not a file or a directory: ${bad//$stage\//}" >&2
  exit 1
fi

when="$(git log -1 --format=%cI HEAD)"
package="$out/lake-rustfs-$version.tar.gz"
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="$when" \
  --format=gnu -cf - . | gzip -n >"$package.partial"
mv -f "$package.partial" "$package"
echo "$package ($(git rev-parse --short HEAD)):"
tar -tzf "$package" | grep -v '/$' | sed 's|^\./|  |'
