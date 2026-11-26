#!/usr/bin/env bash
# What RustFS does with the lake users the adapter's `PUT
# /credentials/{query-engine,sts-issuer}` makes (core decisions 0078 and
# 0091): every call signed with the lake's admin user's keys, never root.
#
# The query engine's user:
#   (admin)  the admin user (the core's admin policy: s3:* on qd-tenant-*,
#            admin:*) may add a canned policy, a user and attach the policy;
#   (again)  the same three calls a second time answer 200 and change
#            nothing: the user still works with the same keys;
#   (rotate) add-user again with another secret for the same access key:
#            the new secret works, the old one is refused;
#   (set)    set-user-or-group-policy replaces a broader policy attached
#            before, it does not add to it;
#   (inside) with the user's keys, in a warehouse (qd-tenant-*): list, put,
#            get, delete an object; the catalog: a namespace made, a table
#            made, listed, loaded and dropped, the namespace dropped;
#   (outside) refused: an object in a bucket that is not a warehouse,
#            making a bucket, another bucket's catalog, the admin API
#            (info, list-users, add-user, add-canned-policy).
# The STS issuer's user (its policy, made the same way):
#   (issuer) it writes in a warehouse and is refused another bucket and
#            the admin API; AssumeRole with a session policy that reads the
#            warehouse gives credentials that list it and are refused a
#            write there and another bucket.
#
# Throwaway containers only (qd-verify-lakeusers-…, a network of their own, no
# port published), random keys never printed, synthetic objects only. Run
# alone (no build at the same time), from the repository root:
#
#   bash tools/verify/rustfs_lake_users.sh
#
# Needs docker, curl 7.75 or later (--aws-sigv4) and openssl.
set -u
export LC_ALL=C
IMAGE=${RUSTFS_IMAGE:-rustfs/rustfs:1.0.5}
docker image inspect "$IMAGE" -f 'image: {{index .RepoDigests 0}}' 2>/dev/null || echo "image: $IMAGE"
P=qd-verify-lakeusers
WAIT=${QD_VERIFY_WAIT:-60}
D=$(mktemp -d)
chmod 700 "$D"
cleanup() {
  docker ps -aq --filter "name=^$P-" | xargs -r docker rm -f >/dev/null 2>&1
  docker network rm "$P" >/dev/null 2>&1
  docker run --rm -v "$D:/d" alpine:3.20 sh -c 'rm -rf /d/drive' >/dev/null 2>&1
  rm -rf "$D"
}
trap cleanup EXIT
FAILED=0
ok() { printf '[OK  ] %s\n' "$*"; }
ko() {
  printf '[FAIL] %s\n' "$*"
  FAILED=1
}
# expect TAG WANT GOT: one check.
expect() {
  if [ "$3" = "$2" ]; then ok "$1 ($3)"; else ko "$1: wanted $2, got $3: $(head -c 300 "$D/out")"; fi
}

docker network create "$P" >/dev/null || exit 1
ROOT_ACCESS="qd$(openssl rand -hex 8)"
ROOT_SECRET=$(openssl rand -hex 20)
printf 'RUSTFS_ACCESS_KEY=%s\nRUSTFS_SECRET_KEY=%s\n' "$ROOT_ACCESS" "$ROOT_SECRET" >"$D/root.env"
chmod 600 "$D/root.env"
# cfg NAME ACCESS SECRET: a curl config, so no key is on a command line.
cfg() {
  printf 'user = "%s:%s"\naws-sigv4 = "aws:amz:us-east-1:s3"\n' "$2" "$3" >"$D/$1.cfg"
  chmod 600 "$D/$1.cfg"
}
cfg root "$ROOT_ACCESS" "$ROOT_SECRET"
mkdir -p "$D/drive"
docker run --rm -v "$D/drive:/x" alpine:3.20 chown 10001:10001 /x >/dev/null
N="$P-node"
docker run -d --name "$N" --network "$P" --env-file "$D/root.env" -e RUSTFS_VOLUMES=/data \
  -v "$D/drive:/data" "$IMAGE" server --address :9000 >/dev/null || exit 1
IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$P\").IPAddress}}" "$N")
URL="http://$IP:9000"
t=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -K "$D/root.cfg" "$URL/")" = 200 ]; do
  t=$((t + 2))
  [ $t -lt "$WAIT" ] || { ko "RustFS not ready after ${WAIT}s"; exit 1; }
  sleep 2
done
ok "RustFS answers"

# as WHO METHOD PATH [FILE]: a request signed with WHO's keys; the code.
as() {
  local f=(--data-binary "")
  [ -z "${4:-}" ] || f=(--data-binary "@$4")
  curl -s -o "$D/out" -w '%{http_code}' --max-time 15 -K "$D/$1.cfg" -X "$2" \
    -H 'content-type: application/json' "${f[@]}" "$URL$3"
}
json() {
  printf '%s' "$2" >"$D/$1.json"
  chmod 600 "$D/$1.json"
}

# The lake's admin user, made by root, as the core's admin-user.sh does.
json admin_policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]},{"Effect":"Allow","Action":["admin:*"],"Resource":["arn:aws:s3:::*"]}]}'
ADMIN_SECRET=$(openssl rand -hex 24)
json admin_user "{\"secretKey\":\"$ADMIN_SECRET\",\"status\":\"enabled\"}"
as root PUT '/rustfs/admin/v3/add-canned-policy?name=qd-platform-admin' "$D/admin_policy.json" >/dev/null
as root PUT '/rustfs/admin/v3/add-user?accessKey=qd-platform-admin' "$D/admin_user.json" >/dev/null
expect "the admin user" 200 "$(as root PUT '/rustfs/admin/v3/set-user-or-group-policy?policyName=qd-platform-admin&userOrGroup=qd-platform-admin&isGroup=false')"
cfg admin qd-platform-admin "$ADMIN_SECRET"

W=qd-tenant-00000000000000000000000000000001
for b in "$W" qd-verify-other; do
  as root PUT "/$b" >/dev/null
  as root PUT "/iceberg/v1/buckets/$b" >/dev/null
done
expect "the warehouse's table bucket" 200 "$(as root GET "/iceberg/v1/config?warehouse=$W")"

# The adapter's query-engine policy (src/credentials.rs), as it sends it.
policy_of() { sed -n "s/^pub const $1: \&str = r#\"\(.*\)\"#;\$/\1/p" crates/lake-rustfs-admin/src/credentials.rs; }
POLICY=$(policy_of QUERY_ENGINE_POLICY)
[ -n "$POLICY" ] || { ko "no QUERY_ENGINE_POLICY in src/credentials.rs"; exit 1; }
json qe_policy "$POLICY"
b64url() { openssl rand -base64 "$1" | tr '+/' '-_' | tr -d '=\n'; }
QE_ACCESS=$(b64url 16)
QE_SECRET=$(b64url 32)
json qe_user "{\"secretKey\":\"$QE_SECRET\",\"status\":\"enabled\"}"
json broad '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}'

ensure() {
  expect "($1) add-canned-policy" 200 "$(as admin PUT '/rustfs/admin/v3/add-canned-policy?name=qd-query-engine' "$D/qe_policy.json")"
  expect "($1) add-user" 200 "$(as admin PUT "/rustfs/admin/v3/add-user?accessKey=$QE_ACCESS" "$D/qe_user.json")"
  expect "($1) set-user-or-group-policy" 200 "$(as admin PUT "/rustfs/admin/v3/set-user-or-group-policy?policyName=qd-query-engine&userOrGroup=$QE_ACCESS&isGroup=false")"
}

# (set) a broader policy attached first, replaced by the query engine's.
as admin PUT '/rustfs/admin/v3/add-canned-policy?name=qd-verify-broad' "$D/broad.json" >/dev/null
as admin PUT "/rustfs/admin/v3/add-user?accessKey=$QE_ACCESS" "$D/qe_user.json" >/dev/null
as admin PUT "/rustfs/admin/v3/set-user-or-group-policy?policyName=qd-verify-broad&userOrGroup=$QE_ACCESS&isGroup=false" >/dev/null
cfg qe "$QE_ACCESS" "$QE_SECRET"
expect "(set) the broad policy reads another bucket" 200 "$(as qe GET '/qd-verify-other?list-type=2')"
ensure admin
expect "(set) replaced: another bucket refused" 403 "$(as qe GET '/qd-verify-other?list-type=2')"
expect "user-info answers the user" 200 "$(as admin GET "/rustfs/admin/v3/user-info?accessKey=$QE_ACCESS")"
grep -q qd-query-engine "$D/out" && ok "user-info names the policy" || ko "user-info: $(head -c 300 "$D/out")"
ensure again
expect "(again) the same keys still list the warehouse" 200 "$(as qe GET "/$W?list-type=2")"

# (inside)
printf 'synthetic row\n' >"$D/obj"
expect "(inside) put an object" 200 "$(as qe PUT "/$W/data/verify/obj.txt" "$D/obj")"
expect "(inside) get it" 200 "$(as qe GET "/$W/data/verify/obj.txt")"
expect "(inside) list" 200 "$(as qe GET "/$W?list-type=2&prefix=data/")"
expect "(inside) delete it" 204 "$(as qe DELETE "/$W/data/verify/obj.txt")"
json ns '{"namespace":["verify_ns"],"properties":{}}'
expect "(inside) a namespace" 200 "$(as qe POST "/iceberg/v1/$W/namespaces" "$D/ns.json")"
json table '{"name":"t1","schema":{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"a","type":"int","required":false}]},"stage-create":false,"properties":{}}'
expect "(inside) a table" 200 "$(as qe POST "/iceberg/v1/$W/namespaces/verify_ns/tables" "$D/table.json")"
expect "(inside) tables listed" 200 "$(as qe GET "/iceberg/v1/$W/namespaces/verify_ns/tables")"
expect "(inside) the table loaded" 200 "$(as qe GET "/iceberg/v1/$W/namespaces/verify_ns/tables/t1")"
code=$(as qe DELETE "/iceberg/v1/$W/namespaces/verify_ns/tables/t1")
case "$code" in 200 | 204) ok "(inside) the table dropped ($code)" ;; *) ko "(inside) the table dropped: $code: $(head -c 300 "$D/out")" ;; esac
code=$(as qe DELETE "/iceberg/v1/$W/namespaces/verify_ns")
case "$code" in 200 | 204) ok "(inside) the namespace dropped ($code)" ;; *) ko "(inside) the namespace dropped: $code: $(head -c 300 "$D/out")" ;; esac

# (outside)
expect "(outside) an object in another bucket" 403 "$(as qe PUT '/qd-verify-other/x.txt' "$D/obj")"
expect "(outside) a new bucket" 403 "$(as qe PUT '/qd-tenant-made-by-the-engine')"
expect "(outside) another bucket's catalog" 403 "$(as qe POST '/iceberg/v1/qd-verify-other/namespaces' "$D/ns.json")"
expect "(outside) admin info" 403 "$(as qe GET '/rustfs/admin/v3/info')"
expect "(outside) admin list-users" 403 "$(as qe GET '/rustfs/admin/v3/list-users')"
expect "(outside) admin add-user" 403 "$(as qe PUT "/rustfs/admin/v3/add-user?accessKey=qdverifyx" "$D/qe_user.json")"
expect "(outside) admin add-canned-policy" 403 "$(as qe PUT '/rustfs/admin/v3/add-canned-policy?name=qd-verify-x' "$D/broad.json")"

# (rotate)
OLD=$QE_SECRET
QE_SECRET=$(b64url 32)
json qe_user "{\"secretKey\":\"$QE_SECRET\",\"status\":\"enabled\"}"
expect "(rotate) add-user with another secret" 200 "$(as admin PUT "/rustfs/admin/v3/add-user?accessKey=$QE_ACCESS" "$D/qe_user.json")"
cfg qe "$QE_ACCESS" "$QE_SECRET"
expect "(rotate) the new secret lists the warehouse" 200 "$(as qe GET "/$W?list-type=2")"
cfg old "$QE_ACCESS" "$OLD"
expect "(rotate) the old secret is refused" 403 "$(as old GET "/$W?list-type=2")"
expect "(rotate) the policy is still attached: another bucket refused" 403 "$(as qe GET '/qd-verify-other?list-type=2')"

# (issuer)
ISSUER_POLICY=$(policy_of STS_ISSUER_POLICY)
[ -n "$ISSUER_POLICY" ] || { ko "no STS_ISSUER_POLICY in src/credentials.rs"; exit 1; }
json issuer_policy "$ISSUER_POLICY"
IS_ACCESS=$(b64url 16)
IS_SECRET=$(b64url 32)
json issuer_user "{\"secretKey\":\"$IS_SECRET\",\"status\":\"enabled\"}"
for run in first again; do
  expect "(issuer, $run) add-canned-policy" 200 "$(as admin PUT '/rustfs/admin/v3/add-canned-policy?name=qd-sts-issuer' "$D/issuer_policy.json")"
  expect "(issuer, $run) add-user" 200 "$(as admin PUT "/rustfs/admin/v3/add-user?accessKey=$IS_ACCESS" "$D/issuer_user.json")"
  expect "(issuer, $run) set-user-or-group-policy" 200 "$(as admin PUT "/rustfs/admin/v3/set-user-or-group-policy?policyName=qd-sts-issuer&userOrGroup=$IS_ACCESS&isGroup=false")"
done
cfg issuer "$IS_ACCESS" "$IS_SECRET"
expect "(issuer) writes in the warehouse" 200 "$(as issuer PUT "/$W/issuer/obj.txt" "$D/obj")"
expect "(issuer) another bucket refused" 403 "$(as issuer GET '/qd-verify-other?list-type=2')"
expect "(issuer) the admin API refused" 403 "$(as issuer GET '/rustfs/admin/v3/list-users')"
SESSION='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket","s3:GetObject"],"Resource":["arn:aws:s3:::'$W'","arn:aws:s3:::'$W'/*"]}]}'
printf 'user = "%s:%s"\naws-sigv4 = "aws:amz:us-east-1:sts"\n' "$IS_ACCESS" "$IS_SECRET" >"$D/issuer_sts.cfg"
chmod 600 "$D/issuer_sts.cfg"
sts=$(curl -s -o "$D/sts.out" -w '%{http_code}' --max-time 15 -K "$D/issuer_sts.cfg" -X POST \
  -H 'content-type: application/x-www-form-urlencoded' --data 'Action=AssumeRole&Version=2011-06-15&DurationSeconds=900' \
  --data-urlencode "Policy=$SESSION" "$URL/")
tmp_access=$(sed -n 's:.*<AccessKeyId>\([^<]*\)</AccessKeyId>.*:\1:p' "$D/sts.out")
tmp_secret=$(sed -n 's:.*<SecretAccessKey>\([^<]*\)</SecretAccessKey>.*:\1:p' "$D/sts.out")
tmp_token=$(sed -n 's:.*<SessionToken>\([^<]*\)</SessionToken>.*:\1:p' "$D/sts.out")
if [ "$sts" = 200 ] && [ -n "$tmp_access" ]; then
  ok "(issuer) AssumeRole with a session policy ($sts)"
  cfg job "$tmp_access" "$tmp_secret"
  printf 'header = "x-amz-security-token: %s"\n' "$tmp_token" >>"$D/job.cfg"
  expect "(issuer) the job's credentials list the warehouse" 200 "$(as job GET "/$W?list-type=2")"
  expect "(issuer) the job's credentials read an object" 200 "$(as job GET "/$W/issuer/obj.txt")"
  expect "(issuer) narrowed: a write refused" 403 "$(as job PUT "/$W/issuer/job.txt" "$D/obj")"
  expect "(issuer) narrowed: another bucket refused" 403 "$(as job GET '/qd-verify-other?list-type=2')"
else
  ko "(issuer) AssumeRole ($sts): $(sed 's/<SecretAccessKey>[^<]*/<SecretAccessKey>…/; s/<SessionToken>[^<]*/<SessionToken>…/' "$D/sts.out" | head -c 300)"
fi

echo
if [ "$FAILED" = 0 ]; then echo "ALL OK"; else echo "SOME CHECKS FAILED"; fi
exit "$FAILED"
