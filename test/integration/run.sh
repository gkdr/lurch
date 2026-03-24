#!/usr/bin/env bash
#
# Integration test runner for lurch OMEMO plugin.
#
# Sets up a Prosody XMPP server in a container, creates test users,
# builds and runs the test harness, then tears everything down.
#
# Usage:
#   ./test/integration/run.sh
#   CONTAINER_RT=podman ./test/integration/run.sh
#   PURPLE_DEBUG=1 ./test/integration/run.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CONTAINER_NAME="lurch-test-prosody"
# prosodyim/prosody:13.0
PROSODY_IMAGE="docker.io/prosodyim/prosody@sha256:099ffd09b342e950aa435a010600316a637cb9be2c3d33717bf2181c85c76c1e"
XMPP_PORT="${XMPP_PORT:-5222}"
RT="${CONTAINER_RT:-docker}"

# ── cleanup ───────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "Cleaning up..."
    $RT rm -f "$CONTAINER_NAME" 2>/dev/null || true
    rm -rf /tmp/lurch_integration_test
}
trap cleanup EXIT

# Remove any leftover container from a previous run
$RT rm -f "$CONTAINER_NAME" 2>/dev/null || true

# ── start prosody ─────────────────────────────────────────────────
echo "Starting Prosody XMPP server..."
$RT run -d \
    --name "$CONTAINER_NAME" \
    -p "${XMPP_PORT}:5222" \
    -v "$SCRIPT_DIR/prosody.cfg.lua:/etc/prosody/prosody.cfg.lua:ro,z" \
    -v "$SCRIPT_DIR/mod_pep_server_disco.lua:/etc/prosody/modules/mod_pep_server_disco.lua:ro,z" \
    "$PROSODY_IMAGE"

# Wait for prosody to be ready
echo -n "Waiting for Prosody to start"
for i in $(seq 1 30); do
    if $RT logs "$CONTAINER_NAME" 2>&1 | grep -q "Activated service 'c2s'"; then
        echo " ready."
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo " TIMEOUT"
        echo "Prosody failed to start. Logs:"
        $RT logs "$CONTAINER_NAME"
        exit 1
    fi
done

# ── create test users and set up mutual rosters ──────────────────
echo "Creating test users and rosters..."
$RT exec -i "$CONTAINER_NAME" prosodyctl shell <<'LUA'
user:create("alice@localhost", "testpass_alice")
user:create("bob@localhost", "testpass_bob")
roster:subscribe_both("alice@localhost", "bob@localhost")
LUA
echo "Users and rosters configured."

# ── build test harness ───────────────────────────────────────────
echo ""
echo "Building test harness..."
cd "$PROJECT_DIR"
make build/test_integration

# ── run tests ────────────────────────────────────────────────────
echo ""
echo "Running integration tests..."
echo ""

exit_code=0
./build/test_integration ./build/lurch.so || exit_code=$?

echo ""
echo "=== Prosody PEP state ==="
$RT exec -i "$CONTAINER_NAME" prosodyctl shell <<'LUA' || true
pubsub:list_nodes("bob@localhost")
pubsub:list_items("bob@localhost", "eu.siacs.conversations.axolotl.devicelist")
pubsub:get_item("bob@localhost", "eu.siacs.conversations.axolotl.devicelist", "current")
pubsub:list_nodes("alice@localhost")
pubsub:list_items("alice@localhost", "eu.siacs.conversations.axolotl.devicelist")
LUA

echo ""
echo "=== Prosody logs (filtered) ==="
$RT logs "$CONTAINER_NAME" 2>&1 | grep -iE "pep|pubsub|discard|notification|Sending notification|publish|subscribe" | grep -v "admin_shell" || true

exit $exit_code
