#!/bin/sh
# RustFS's drives on one node (core decision 0091, point 3): the first
# entrypoint of the service `rustfs` in compose.yml, before rustfs-tls.sh.
#
# LAKE_DRIVES is how many drives the node has, each a disk of its own:
#   1 (the default)  RustFS keeps its data in /data itself (RUSTFS_VOLUMES
#                    /data). Allowed, but such a node never grows in place:
#                    RustFS refuses more drives or an added pool beside it.
#   N, 2 or more     RustFS keeps its data in /data/1 to /data/N
#                    (RUSTFS_VOLUMES /data/{1...N}), one erasure-coded set,
#                    to which a pool of new nodes can later be added. Four
#                    is advised.
# The number is the node's for good: RustFS refuses to start when it
# changes. Each /data/<n> must be a mount point of its own (LAKE_DATA in
# compose.yml), as RustFS refuses two drives on one disk; this script says
# which one is not, before RustFS does.
set -eu
DRIVES=${LAKE_DRIVES:-1}

fail() {
  echo "rustfs-drives: $*" >&2
  exit 1
}

case "$DRIVES" in
  '' | *[!0-9]* | 0*) fail "LAKE_DRIVES is $DRIVES: it must be 1 or more" ;;
esac
[ "$DRIVES" -le 32 ] || fail "LAKE_DRIVES is $DRIVES: at most 32 drives on one node"

if [ "$DRIVES" = 1 ]; then
  RUSTFS_VOLUMES=/data
else
  parent=$(stat -c %d /data)
  n=1
  while [ "$n" -le "$DRIVES" ]; do
    [ -d "/data/$n" ] || fail "LAKE_DRIVES is $DRIVES but there is no drive $n (/data/$n)"
    [ "$(stat -c %d "/data/$n")" != "$parent" ] ||
      fail "drive $n (/data/$n) is not a disk of its own: mount one there"
    n=$((n + 1))
  done
  RUSTFS_VOLUMES="/data/{1...$DRIVES}"
fi
export RUSTFS_VOLUMES
echo "rustfs-drives: $DRIVES drive(s), RUSTFS_VOLUMES=$RUSTFS_VOLUMES" >&2

exec /etc/qd/rustfs/tls.sh "$@"
