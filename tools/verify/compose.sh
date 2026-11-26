#!/usr/bin/env bash
# Checks compose.yml against Docker and RustFS, offline, with invented keys
# and data only:
#
#   tools/verify/compose.sh
#
# Runs `rustfs`, `gate` and `admin` from this checkout's compose.yml as the
# project qs-verify-lake, with a throwaway CA and machine certificate (its
# name and admin.<its name>), a fake core lake check (traefik/whoami over
# TLS) and, in place of the adapter's image, a stand-in that does mTLS
# itself with a certificate of its own (traefik/whoami with -cacert; a
# compose override). Everything goes through the gate's one published port
# (RUSTFS_PORT, mapped here to a free high port). For one drive (the volume
# rustfs-data) and for four (four tmpfs mounted under LAKE_DATA by a
# privileged helper, each a device of its own):
#   - S3 under the machine's name: an object written and read back through
#     the gate with a machine certificate; refused without one, and refused
#     when the check says no;
#   - the adapter under admin.<name> on the same port: answered by the
#     stand-in, whose own certificate is the one presented (the gate does
#     not terminate it), refused by the stand-in without a client
#     certificate, and still answered when the core's check says no;
#   - the agent's backup of /data (`docker compose cp rustfs:/data -`), the
#     volume emptied as its restore does (busybox find -delete through
#     --volumes-from) and copied back: the object reads back.
# And four drives asked of a node with no disks under /data: refused.
# Run it alone (no build at the same time); everything is removed in a trap.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
P=qs-verify-lake
W="$(mktemp -d)"
export IMAGE_RUSTFS="${IMAGE_RUSTFS:-rustfs/rustfs:1.0.5}"
export IMAGE_GATE="${IMAGE_GATE:-traefik:v3.6}"
export IMAGE_ADMIN=traefik/whoami:v1.11
HELPER=alpine:3.20
RUSTFS_ACCESS_KEY="qsverify$(openssl rand -hex 6)" RUSTFS_SECRET_KEY="$(openssl rand -hex 20)"
export RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY
export QD_MACHINE_NAME=qs-verify-lake-1 QD_MACHINE_DIR="$W/machine"
export QD_LAKE_CHECK_URL=https://qs-verify-check/health
export RUSTFS_BIND=127.0.0.1 RUSTFS_PORT=19100
ADMIN_NAME="admin.$QD_MACHINE_NAME"
failed=0

dc() { docker compose --project-name "$P" --project-directory "$root" --file "$root/compose.yml" \
  --file "$W/stand-in.yml" "$@"; }
ok() { echo "PASS $*"; }
bad() { echo "FAIL $*"; failed=1; }
# The drives' mounts outlive their helper: unmounted from a peer of them.
unmount() {
  docker run --rm --privileged -v "$W:/w:rshared" --entrypoint umount "$HELPER" \
    /w/drives/1 /w/drives/2 /w/drives/3 /w/drives/4 >/dev/null 2>&1 || true
  docker rm -f qs-verify-drives >/dev/null 2>&1 || true
}
cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f qs-verify-check >/dev/null 2>&1 || true
  unmount
  # The files the containers' root wrote, then the directory, only if it is
  # still mktemp's.
  docker run --rm -v "$W:/w" --entrypoint find "$HELPER" /w -mindepth 1 -delete >/dev/null 2>&1 || true
  case "$W" in */tmp.*) rmdir -- "$W" 2>/dev/null || true ;; esac
}
trap cleanup EXIT

# A CA, the lake machine's certificate (machine.pem: certificate then key),
# the fake core's and a client's; readable by the containers' uid 10001.
mkdir -p "$W/machine" "$W/check" "$W/client" "$W/admin"
cert() { # name dir [alt names, comma-separated DNS:…]
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$2/key.pem" \
    -subj "/CN=$1" -out "$2/req.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "${3:-DNS:$1}" >"$2/ext"
  openssl x509 -req -in "$2/req.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial \
    -days 1 -extfile "$2/ext" -out "$2/cert.pem" 2>/dev/null
}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/ca.key" \
  -subj "/CN=qs-verify CA" -days 1 -out "$W/ca.crt" 2>/dev/null
cert "$QD_MACHINE_NAME" "$W/machine" "DNS:$QD_MACHINE_NAME,DNS:$ADMIN_NAME"
cat "$W/machine/cert.pem" "$W/machine/key.pem" >"$W/machine/machine.pem"
cp "$W/ca.crt" "$W/machine/ca.crt"
cert qs-verify-check "$W/check"
cert qs-verify-client "$W/client"
# The stand-in's own certificate, for admin.<name> but not the machine's:
# the one a client sees only if the gate passes the TLS through.
cert qs-verify-admin-stand-in "$W/admin" "DNS:$ADMIN_NAME"
cp "$W/ca.crt" "$W/admin/ca.crt"
# The adapter's service as compose.yml has it, its image a stand-in.
cat >"$W/stand-in.yml" <<YML
services:
  admin:
    command: ["--port", "9020", "--cert", "/s/cert.pem", "--key", "/s/key.pem", "--cacert", "/s/ca.crt"]
    volumes:
      - $W/admin:/s:ro
YML
chmod -R a+rX "$W"

# One case: up, an object through the gate, the refusals, backup and restore.
run_case() { # label
  local label="$1" url body="qs-verify $1 $RANDOM"
  local tls=(--cacert "$W/ca.crt" --resolve "$QD_MACHINE_NAME:$RUSTFS_PORT:127.0.0.1")
  local s3=("${tls[@]}" --cert "$W/client/cert.pem" --key "$W/client/key.pem"
    --aws-sigv4 aws:amz:us-east-1:s3 --user "$RUSTFS_ACCESS_KEY:$RUSTFS_SECRET_KEY")
  url="https://$QD_MACHINE_NAME:$RUSTFS_PORT"
  if ! dc up -d --wait --wait-timeout 180 rustfs gate admin >/dev/null 2>&1; then
    bad "$label: rustfs, gate and admin up"; dc logs rustfs gate admin | tail -20; return
  fi
  docker network connect --alias qs-verify-check "${P}_edge" qs-verify-check
  sleep 3
  if curl "${s3[@]}" -fsS -X PUT "$url/qs-verify" -o /dev/null &&
    curl "${s3[@]}" -fsS -X PUT --data-binary "$body" "$url/qs-verify/object" -o /dev/null &&
    [ "$(curl "${s3[@]}" -fsS "$url/qs-verify/object")" = "$body" ]; then
    ok "$label: an object written and read back through the gate"
  else bad "$label: an object through the gate"; fi
  if curl "${tls[@]}" -fsS "$url/health/ready" -o /dev/null 2>/dev/null; then
    bad "$label: the gate let in a client with no certificate"
  else ok "$label: no client certificate, refused"; fi
  admin_route "$label" 200
  check 403
  if [ "$(curl "${s3[@]}" -sS -o /dev/null -w '%{http_code}' "$url/qs-verify/object")" = 403 ]; then
    ok "$label: the core's check says no, refused"
  else bad "$label: the gate did not follow the core's check"; fi
  admin_route "$label" 403
  check 200
  dc cp rustfs:/data - >"$W/backup.tar"
  dc stop rustfs >/dev/null 2>&1
  docker run --rm --volumes-from "$P-rustfs-1" --entrypoint find "$HELPER" /data -mindepth 1 -delete 2>/dev/null || true
  dc cp - rustfs:/ <"$W/backup.tar"
  dc start rustfs >/dev/null 2>&1
  local i=0
  until [ "$(curl "${s3[@]}" -fsS "$url/qs-verify/object" 2>/dev/null)" = "$body" ]; do
    i=$((i + 1)); [ "$i" -lt 30 ] || break; sleep 2
  done
  if [ "$i" -lt 30 ]; then ok "$label: /data backed up, emptied, restored: the object reads back"
  else bad "$label: the object after a restore of /data"; fi
  rm -f -- "$W/backup.tar"
  docker network disconnect "${P}_edge" qs-verify-check
  dc down -v >/dev/null 2>&1
}

# admin.<name> on the gate's one port: the stand-in's own certificate is
# the one presented (the gate passed the TLS through), it answers a client
# certificate and refuses none itself. With the check answering $2, which
# the adapter's route does not ask.
admin_route() { # label check
  local label="$1" at="https://$ADMIN_NAME:$RUSTFS_PORT/"
  local tls=(--cacert "$W/ca.crt" --resolve "$ADMIN_NAME:$RUSTFS_PORT:127.0.0.1")
  local subject
  subject=$(openssl s_client -connect "127.0.0.1:$RUSTFS_PORT" -servername "$ADMIN_NAME" \
    -cert "$W/client/cert.pem" -key "$W/client/key.pem" </dev/null 2>/dev/null |
    openssl x509 -noout -subject 2>/dev/null)
  case "$subject" in
  *qs-verify-admin-stand-in*) ok "$label: admin.<name> passed through to the adapter, not terminated" ;;
  *) bad "$label: admin.<name> was answered by '$subject', not the adapter" ;;
  esac
  if curl "${tls[@]}" --cert "$W/client/cert.pem" --key "$W/client/key.pem" -fsS "$at" |
    grep -q '^Hostname:'; then
    ok "$label: the adapter answers a client certificate (check $2)"
  else bad "$label: the adapter through the gate (check $2)"; fi
  if curl "${tls[@]}" -fsS "$at" -o /dev/null 2>/dev/null; then
    bad "$label: the adapter's route let in a client with no certificate"
  else ok "$label: the adapter's route, no client certificate, refused"; fi
}

# What the fake core's lake check answers from now on.
check() {
  curl --cacert "$W/ca.crt" --resolve qs-verify-check:19443:127.0.0.1 -fsS -X POST -d "$1" \
    https://qs-verify-check:19443/health -o /dev/null
}

docker run -d --name qs-verify-check -p 127.0.0.1:19443:443 -v "$W/check:/c:ro" traefik/whoami:v1.11 \
  --port 443 --cert /c/cert.pem --key /c/key.pem >/dev/null

# One drive, in the volume rustfs-data.
unset LAKE_DATA; export LAKE_DRIVES=1
run_case "one drive"

# Four drives: four tmpfs, each a device of its own, under LAKE_DATA.
mkdir -p "$W/drives" && chmod 755 "$W/drives"
docker run -d --name qs-verify-drives --privileged -v "$W:/w:rshared" "$HELPER" sh -c \
  'for n in 1 2 3 4; do mkdir -p /w/drives/$n && mount -t tmpfs -o size=256m,uid=10001,gid=10001 qs-verify-$n /w/drives/$n; done; exec sleep 3600' >/dev/null
for _ in $(seq 1 20); do [ "$(findmnt -rno TARGET | grep -c "^$W/drives/")" = 4 ] && break; sleep 1; done
export LAKE_DATA="$W/drives" LAKE_DRIVES=4
run_case "four drives"
unmount

# Four drives asked of /data with no disk of its own: refused.
export LAKE_DRIVES=4
unset LAKE_DATA
dc up -d rustfs >/dev/null 2>&1 || true
sleep 5
if dc logs rustfs 2>&1 | grep -qE "no drive 1|is not a disk of its own"; then
  ok "four drives with no disks under /data: refused"
else bad "four drives with no disks under /data were not refused"; dc logs rustfs | tail -5; fi
dc down -v >/dev/null 2>&1

[ "$failed" = 0 ] && echo "PASS all" || { echo "FAIL"; exit 1; }
