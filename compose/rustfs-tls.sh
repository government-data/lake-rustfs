#!/bin/sh
# RustFS with the machine's certificate (decision 0066, points 10 and 13,
# step 10): the entrypoint of the service `rustfs` in
# infra/rustfs/certificate.yml, run as RustFS's own user (uid 10001) before
# the image's entrypoint.
#
# The lake node's agent keeps its files in its directory, mounted read-only
# at QD_RUSTFS_TLS_SOURCE, as this user's (the agent runs as uid 10001):
# `ca.crt`, the installation's CA, and `machine.pem`, the certificate then
# the key, renamed whole at each renewal. RustFS reads its TLS directory
# (RUSTFS_TLS_PATH) as three files of its own: `rustfs_cert.pem`,
# `rustfs_key.pem` and `client_ca.crt`, and `ca.crt` when RustFS is to
# trust the CA for its own calls out too (QD_RUSTFS_TLS_TRUST_CA=1: a lake
# replica's, whose RustFS makes no call to the public address; a pool's
# nodes need it to reach each other), and `client_cert.pem` and
# `client_key.pem`, the same certificate and key, which a pool's node
# presents to its peers (QD_RUSTFS_TLS_CLIENT=1: RustFS 1.0.5 re-reads them
# as it re-reads its own, and a peer that restarts refuses an expired one;
# tools/verify/rustfs_pool_nodes.sh). So they are written here from the
# agent's, once before RustFS starts and again whenever the agent's change
# (looked at every QD_RUSTFS_TLS_CHECK_EVERY seconds); RustFS re-reads its
# directory by itself (RUSTFS_TLS_RELOAD_ENABLE) without a restart. Each
# file is written aside first, and the key and the certificate are renamed
# one right after the other: RustFS refuses a pair that does not match and
# keeps serving the one it has, so a reload between the two renames is
# only put off to the next.
#
# The watcher is detached from RustFS (a child of the container's init,
# `init: true`), so RustFS never has a child it did not start.
set -eu
SRC=${QD_RUSTFS_TLS_SOURCE:-/run/qd-node}
DST=${RUSTFS_TLS_PATH:?set RUSTFS_TLS_PATH}
EVERY=${QD_RUSTFS_TLS_CHECK_EVERY:-30}
WAIT=${QD_RUSTFS_TLS_WAIT:-300}
TRUST_CA=${QD_RUSTFS_TLS_TRUST_CA:-0}
CLIENT=${QD_RUSTFS_TLS_CLIENT:-0}

log() { echo "rustfs-tls: $*" >&2; }

present() { [ -s "$SRC/ca.crt" ] && [ -s "$SRC/machine.pem" ]; }

# What the agent's files are now. Never printed.
fingerprint() { cat "$SRC/ca.crt" "$SRC/machine.pem" 2>/dev/null | sha256sum | cut -d' ' -f1; }

# The certificate and the key out of machine.pem, aside, then renamed.
install_files() {
  umask 077
  awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$SRC/machine.pem" >"$DST/.rustfs_cert.pem.new"
  awk '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/' "$SRC/machine.pem" >"$DST/.rustfs_key.pem.new"
  cp "$SRC/ca.crt" "$DST/.client_ca.crt.new"
  [ "$TRUST_CA" != 1 ] || cp "$SRC/ca.crt" "$DST/.ca.crt.new"
  if [ "$CLIENT" = 1 ]; then
    cp "$DST/.rustfs_cert.pem.new" "$DST/.client_cert.pem.new"
    cp "$DST/.rustfs_key.pem.new" "$DST/.client_key.pem.new"
  fi
  if ! [ -s "$DST/.rustfs_cert.pem.new" ] || ! [ -s "$DST/.rustfs_key.pem.new" ]; then
    log "machine.pem has no certificate or no key: not installed"
    return 1
  fi
  mv -f "$DST/.client_ca.crt.new" "$DST/client_ca.crt"
  [ "$TRUST_CA" != 1 ] || mv -f "$DST/.ca.crt.new" "$DST/ca.crt"
  mv -f "$DST/.rustfs_key.pem.new" "$DST/rustfs_key.pem"
  mv -f "$DST/.rustfs_cert.pem.new" "$DST/rustfs_cert.pem"
  if [ "$CLIENT" = 1 ]; then
    mv -f "$DST/.client_key.pem.new" "$DST/client_key.pem"
    mv -f "$DST/.client_cert.pem.new" "$DST/client_cert.pem"
  fi
}

watch() {
  current=$1
  while sleep "$EVERY"; do
    present || continue
    now=$(fingerprint)
    [ "$now" = "$current" ] && continue
    if install_files; then
      current=$now
      log "the renewed certificate installed; RustFS reloads it by itself"
    fi
  done
}

waited=0
until present; do
  if [ "$waited" -ge "$WAIT" ]; then
    log "no ca.crt and machine.pem in $SRC after ${WAIT}s: is the node agent running?"
    exit 1
  fi
  [ "$waited" = 0 ] && log "waiting for the node agent's files in $SRC"
  sleep 2
  waited=$((waited + 2))
done
mkdir -p "$DST"
install_files
log "the machine's certificate installed"
# Detached: the subshell exits at once, so the watcher's parent is the init.
(watch "$(fingerprint)" &)

# RustFS's metrics, pushed over OTLP to the node's Alloy, carry the node's
# token (decision 0071, the user's ruling of 2026-11-14), which join.sh made
# (QD_RUSTFS_OBS_TOKEN_FILE). It is read here, so that it is in RustFS's
# environment alone and in no container setting `docker inspect` shows, and
# never printed.
TOKEN_FILE=${QD_RUSTFS_OBS_TOKEN_FILE:-}
if [ -n "$TOKEN_FILE" ]; then
  if [ -s "$TOKEN_FILE" ]; then
    RUSTFS_OBS_ENDPOINT_METRICS_HEADERS="authorization=Bearer $(cat "$TOKEN_FILE")"
    export RUSTFS_OBS_ENDPOINT_METRICS_HEADERS
  else
    log "no token in $TOKEN_FILE: RustFS's metrics would be refused"
  fi
fi

exec /entrypoint.sh "$@"
