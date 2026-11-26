#!/bin/zsh
# Runs one wisp-loadgen scenario against a wispd binary and prints the result
# with the server's CPU time. Interleave runs of two binaries to compare them;
# on a busy machine, differences under about 20 % are noise.
#
# Build wispd WebSocket-only: the default build links msquic as a dylib that
# a binary run straight from target/ cannot find.
#
#   cargo build --release -p wisp-loadgen
#   cargo build --release -p wispd --no-default-features --features ws
#   cp target/release/wispd /tmp/wispd-before    # build the other side too
#   bench/ab.sh /tmp/wispd-before before bulk 2 10 512 5
#   bench/ab.sh target/release/wispd after bulk 2 10 512 5
#
# usage: ab.sh <wispd-binary> <label> <bulk|rr|churn|churn-client-close> <conns> <streams> <payload> <secs>
set -eu
if (( $# != 7 )); then
  print -u2 "usage: ab.sh <wispd-binary> <label> <bulk|rr|churn|churn-client-close> <conns> <streams> <payload> <secs>"
  exit 2
fi
root="${0:A:h:h}"
bin="$1"; label="$2"; shift 2
loadgen="$root/target/release/wisp-loadgen"
log="${TMPDIR:-/tmp}/wispd-ab-$label.log"

"$bin" --config "$root/configs/wispd.test.toml" --log-level error > "$log" 2>&1 &
pid=$!
trap 'kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null || true' EXIT
until nc -z 127.0.0.1 6001 2>/dev/null; do
  kill -0 $pid 2>/dev/null || { print -u2 "wispd exited; see $log"; exit 1; }
  sleep 0.1
done
out=$("$loadgen" "$1" 6001 6002 "$2" "$3" "$4" "$5" 2>&1 | tail -1)
cpu=$(ps -o cputime= -p $pid | awk -F'[:.]' '{print $1*60+$2+$3/100}')
print "$label | $out | server_cpu=${cpu}s"
