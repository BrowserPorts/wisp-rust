#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXCLUDES_FILE="$SCRIPT_DIR/rsync-excludes.txt"
PROVIDERS_DIR="${WISPD_PROVIDERS_DIR:-$(cd "$REPO_ROOT/../wisp-rust-proxy-providers" && pwd)}"
CONFIG_FILE="${WISPD_CONFIG_FILE:-$REPO_ROOT/configs/wispd.production.toml}"
TARGETS="${WISPD_TARGETS:-primary secondary}"

PRIMARY_HOST="${WISPD_PRIMARY_HOST:-${WISPD_HOST:-root@5.188.124.21}}"
PRIMARY_REMOTE_DIR="${WISPD_PRIMARY_REMOTE_DIR:-/opt/wisp-rust}"
PRIMARY_PORT="${WISPD_PRIMARY_PORT:-${WISPD_PORT:-4242}}"
PRIMARY_SERVICE="${WISPD_PRIMARY_SERVICE:-wispd}"

SECONDARY_HOST="${WISPD_SECONDARY_HOST:-root@92.38.177.25}"
SECONDARY_REMOTE_DIR="${WISPD_SECONDARY_REMOTE_DIR:-/opt/wisp-rust}"
SECONDARY_PORT="${WISPD_SECONDARY_PORT:-${WISPD_PORT:-4242}}"
SECONDARY_SERVICE="${WISPD_SECONDARY_SERVICE:-wispd}"

probe_host() {
  local host="$1"
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "true" >/dev/null 2>&1
}

deploy_target() {
  local target_name="$1"
  local host="$2"
  local remote_dir="$3"
  local port="$4"
  local service_name="$5"
  local required="$6"

  if ! probe_host "$host"; then
    if [ "$required" = "false" ]; then
      echo "Skipping ${target_name}: ${host} unreachable" >&2
      return 0
    fi
    echo "Unable to connect to ${target_name} (${host})" >&2
    return 1
  fi

  local providers_remote_dir
  providers_remote_dir="$(dirname "$remote_dir")/wisp-rust-proxy-providers"

  ssh "$host" "if ! command -v rsync >/dev/null 2>&1; then apt-get update && apt-get install -y rsync; fi; mkdir -p '$remote_dir' '$providers_remote_dir' /etc/wispd"

  echo "Syncing ${target_name} wisp-rust repository"
  rsync -azP --delete \
    --exclude-from "$EXCLUDES_FILE" \
    "$REPO_ROOT/" "$host:$remote_dir/"

  echo "Syncing ${target_name} wisp-rust-proxy-providers repository"
  rsync -azP --delete \
    --exclude-from "$EXCLUDES_FILE" \
    "$PROVIDERS_DIR/" "$host:$providers_remote_dir/"

  if [ -f "$CONFIG_FILE" ]; then
    echo "Syncing ${target_name} wispd config"
    rsync -azP "$CONFIG_FILE" "$host:/etc/wispd/wispd.toml"
    ssh "$host" "chmod 600 /etc/wispd/wispd.toml"
  fi

  echo "Running ${target_name} deploy"
  ssh "$host" \
    "REMOTE_DIR='$remote_dir' WISPD_PORT='$port' SERVICE_NAME='$service_name' bash -se" <<'EOF'
set -euo pipefail
cd "$REMOTE_DIR"
export PATH="/root/.cargo/bin:$PATH"

DEPLOY_STEP='Initializing deploy'
trap 'echo "Deploy failed while ${DEPLOY_STEP}" >&2' ERR

deploy_step() {
  DEPLOY_STEP="$1"
  echo "$DEPLOY_STEP"
}

exec 9>/tmp/${SERVICE_NAME}-deploy.lock
if ! flock -n 9; then
  echo "Another wispd deploy is already running on this host." >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v cc >/dev/null 2>&1 || ! command -v pkg-config >/dev/null 2>&1; then
  deploy_step 'Updating package index'
  apt-get update
fi

if ! command -v cc >/dev/null 2>&1; then
  deploy_step 'Installing build essentials'
  apt-get install -y build-essential pkg-config libssl-dev ca-certificates curl
fi

if ! command -v redis-server >/dev/null 2>&1; then
  deploy_step 'Installing redis'
  apt-get install -y redis-server
  systemctl enable redis-server
  systemctl restart redis-server
fi

if ! command -v cargo >/dev/null 2>&1; then
  deploy_step 'Installing rustup + stable toolchain'
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
fi

deploy_step 'Building wispd (release, ws-only)'
cargo build --release -p wispd --no-default-features --features ws

if [ ! -x "$REMOTE_DIR/target/release/wispd" ]; then
  echo "wispd binary missing after build at $REMOTE_DIR/target/release/wispd" >&2
  exit 1
fi

deploy_step 'Writing systemd unit'
cat >/etc/systemd/system/${SERVICE_NAME}.service <<UNIT
[Unit]
Description=Wisp v2 (Rust) WebSocket transport
Documentation=https://github.com/browser-ports/wisp-rust
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${REMOTE_DIR}
ExecStart=${REMOTE_DIR}/target/release/wispd --config /etc/wispd/wispd.toml
Restart=always
RestartSec=5
User=root
Group=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
LimitNOFILE=1048576
MemoryMax=1G
Environment=RUST_LOG=info
Environment=WISPD_PORT=${WISPD_PORT}

[Install]
WantedBy=multi-user.target
UNIT

deploy_step 'Reloading systemd'
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

deploy_step 'Restarting wispd'
systemctl restart "$SERVICE_NAME"

deploy_step 'Reading service status'
systemctl status "$SERVICE_NAME" --no-pager || true
EOF
}

for target in ${TARGETS//,/ }; do
  case "$target" in
    primary)
      deploy_target primary "$PRIMARY_HOST" "$PRIMARY_REMOTE_DIR" "$PRIMARY_PORT" "$PRIMARY_SERVICE" false || true
      ;;
    secondary)
      deploy_target secondary "$SECONDARY_HOST" "$SECONDARY_REMOTE_DIR" "$SECONDARY_PORT" "$SECONDARY_SERVICE" false || true
      ;;
    all)
      deploy_target primary "$PRIMARY_HOST" "$PRIMARY_REMOTE_DIR" "$PRIMARY_PORT" "$PRIMARY_SERVICE" false || true
      deploy_target secondary "$SECONDARY_HOST" "$SECONDARY_REMOTE_DIR" "$SECONDARY_PORT" "$SECONDARY_SERVICE" false || true
      ;;
    *)
      echo "Unknown deploy target ${target}" >&2
      exit 1
      ;;
  esac
done
