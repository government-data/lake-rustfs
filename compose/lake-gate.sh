#!/bin/sh
# The lake's gate (decision 0066, point 10): the entrypoint of the service
# `gate` in infra/rustfs/gate.yml, a Traefik in front of RustFS run as the
# node agent's user (uid 10001).
#
# It writes the gate's one dynamic file, in a tmpfs, from the environment:
#   - TLS with the lake node's machine certificate (the agent's
#     `machine.pem`, the certificate then the key, read as both), and a
#     client certificate of the installation's CA (`ca.crt`) required of
#     everyone;
#   - before each request, forwardAuth to QD_LAKE_CHECK_URL (the API's
#     /api/internal/machines/lake/check on the application's entry point
#     of the gates), presenting the same machine certificate, with the
#     machine at the door named in X-Forwarded-Tls-Client-Cert-Info
#     (subject and serial), which Traefik writes over whatever came;
#   - then RustFS, over TLS verified against the CA under the node's name
#     (QD_MACHINE_NAME, its certificate's), presenting the same machine
#     certificate, which a pool node's RustFS requires of every client
#     (tools/verify/rustfs_pool_nodes.sh) and the others do not ask: its S3
#     and admin API on port 9000 (QD_GATE_UPSTREAM), and its console, which RustFS 1.0.5 serves only on its own port
#     (9001), for the paths under /rustfs/console. The console is reached
#     as everything else: with a machine's certificate, the application
#     VM's, whose Traefik people's browsers go through.
# Traefik reads a certificate's file when it reads the configuration that
# names it and watches that file alone, so when the agent renews
# `machine.pem` (looked at every QD_GATE_CHECK_EVERY seconds) the file is
# written again and Traefik takes the certificate without a restart.
#
# The watcher is detached (a child of the container's init, `init: true`).
set -eu
SRC=${QD_GATE_SOURCE:-/run/qd-node}
DYN=${QD_GATE_DYNAMIC:-/run/qd-gate}
EVERY=${QD_GATE_CHECK_EVERY:-30}
WAIT=${QD_GATE_WAIT:-300}
: "${QD_LAKE_CHECK_URL:?set QD_LAKE_CHECK_URL to the API's lake check on the gates' entry point}"
: "${QD_MACHINE_NAME:?set QD_MACHINE_NAME to the lake node's name, its certificate's}"
UPSTREAM=${QD_GATE_UPSTREAM:-https://rustfs:9000}
CONSOLE=${QD_GATE_CONSOLE_UPSTREAM:-https://rustfs:9001}

log() { echo "lake-gate: $*" >&2; }
present() { [ -s "$SRC/ca.crt" ] && [ -s "$SRC/machine.pem" ]; }
# What the agent's files are now. Never printed.
fingerprint() { cat "$SRC/ca.crt" "$SRC/machine.pem" 2>/dev/null | sha256sum | cut -d' ' -f1; }

# The dynamic file, aside then renamed.
write() {
  cat >"$DYN/.gate.yml.new" <<YML
http:
  routers:
    lake:
      entryPoints: [lake]
      rule: "PathPrefix(\`/\`)"
      tls: {}
      middlewares: [machine, ask]
      service: rustfs
    console:
      entryPoints: [lake]
      rule: "PathPrefix(\`/rustfs/console\`)"
      tls: {}
      middlewares: [machine, ask]
      service: console
  middlewares:
    machine:
      passTLSClientCert:
        info:
          serialNumber: true
          subject:
            organization: true
            organizationalUnit: true
            commonName: true
    ask:
      forwardAuth:
        address: "$QD_LAKE_CHECK_URL"
        tls:
          ca: $SRC/ca.crt
          cert: $SRC/machine.pem
          key: $SRC/machine.pem
  services:
    rustfs:
      loadBalancer:
        serversTransport: rustfs
        servers:
          - url: "$UPSTREAM"
    console:
      loadBalancer:
        serversTransport: rustfs
        servers:
          - url: "$CONSOLE"
  serversTransports:
    rustfs:
      serverName: "$QD_MACHINE_NAME"
      rootCAs: [$SRC/ca.crt]
      certificates:
        - certFile: $SRC/machine.pem
          keyFile: $SRC/machine.pem
tls:
  options:
    default:
      minVersion: VersionTLS12
      clientAuth:
        caFiles: [$SRC/ca.crt]
        clientAuthType: RequireAndVerifyClientCert
  stores:
    default:
      defaultCertificate:
        certFile: $SRC/machine.pem
        keyFile: $SRC/machine.pem
YML
  mv -f "$DYN/.gate.yml.new" "$DYN/gate.yml"
}

watch() {
  current=$1
  while sleep "$EVERY"; do
    present || continue
    now=$(fingerprint)
    [ "$now" = "$current" ] && continue
    write
    current=$now
    log "the renewed certificate is read again"
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
mkdir -p "$DYN"
write
(watch "$(fingerprint)" &)

exec traefik --providers.file.directory="$DYN" --providers.file.watch=true \
  --entrypoints.lake.address=:9000 \
  --entrypoints.lake.transport.respondingTimeouts.readTimeout="${QD_GATE_READ_TIMEOUT:-0s}" \
  --log.level="${QD_GATE_LOG_LEVEL:-ERROR}" "$@"
