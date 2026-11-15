#!/usr/bin/env bash
#
# Integration test runner for lurch OMEMO plugin.
#
# Builds the test harness, then runs every scenario against its own
# fresh Prosody container (and fresh client user dirs), so scenarios
# never share server state. The scenario list comes from the harness
# (`build/test_integration --list`).
#
# Usage:
#   make test-integration
#   CONTAINER_RT=podman make test-integration
#   PURPLE_DEBUG=1 make test-integration
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CONTAINER_NAME="lurch-test-prosody"
# prosodyim/prosody:13.0
PROSODY_IMAGE="docker.io/prosodyim/prosody@sha256:099ffd09b342e950aa435a010600316a637cb9be2c3d33717bf2181c85c76c1e"
XMPP_PORT="${XMPP_PORT:-5222}"
RT="${CONTAINER_RT:-docker}"
HARNESS="$PROJECT_DIR/build/test_integration"
DEVICELIST_NODE="eu.siacs.conversations.axolotl.devicelist"

# ── helpers ───────────────────────────────────────────────────────

# Removes the container and the client user dirs.
reset_env() {
    $RT rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf /tmp/lurch_integration_test /tmp/lurch_integration_test_dev2
}

# Runs one non-interactive prosodyctl shell command in the container.
pshell() {
    $RT exec "$CONTAINER_NAME" prosodyctl shell "$@"
}

# Starts a fresh Prosody, waits for c2s, and creates users + rosters.
start_prosody() {
    reset_env

    echo "Starting Prosody XMPP server..."
    $RT run -d \
        --name "$CONTAINER_NAME" \
        -p "${XMPP_PORT}:5222" \
        -v "$SCRIPT_DIR/prosody.cfg.lua:/etc/prosody/prosody.cfg.lua:ro,z" \
        -v "$SCRIPT_DIR/mod_pep_server_disco.lua:/etc/prosody/modules/mod_pep_server_disco.lua:ro,z" \
        "$PROSODY_IMAGE" >/dev/null

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
            return 1
        fi
    done

    echo "Creating test users and rosters..."
    $RT exec -i "$CONTAINER_NAME" prosodyctl shell >/dev/null <<'LUA'
user:create("alice@localhost", "testpass_alice")
user:create("bob@localhost", "testpass_bob")
user:create("charlie@localhost", "testpass_charlie")
roster:subscribe_both("alice@localhost", "bob@localhost")
roster:subscribe_both("alice@localhost", "charlie@localhost")
LUA
    echo "Users and rosters configured."
}

# Prints the PEP state and filtered server log, for debugging.
dump_server_state() {
    echo ""
    echo "=== Prosody PEP state ==="
    for user in alice@localhost bob@localhost; do
        echo "--- $user"
        pshell pubsub list_nodes "$user" || true
        pshell pubsub list_items "$user" "$DEVICELIST_NODE" || true
    done

    echo ""
    echo "=== Prosody logs (filtered) ==="
    $RT logs "$CONTAINER_NAME" 2>&1 \
        | grep -iE "pep|pubsub|discard|notification|publish|subscribe" \
        | grep -v "admin_shell" || true
}

trap reset_env EXIT

# ── build ─────────────────────────────────────────────────────────
echo "Building test harness..."
cd "$PROJECT_DIR"
make build/test_integration build/lurch.so build/carbons.so

# ── pick scenarios ────────────────────────────────────────────────
mapfile -t scenarios < <("$HARNESS" --list | cut -f1)

# ── run ───────────────────────────────────────────────────────────
failed=()
for scenario in "${scenarios[@]}"; do
    echo ""
    echo "################ scenario: $scenario ################"
    start_prosody

    rc=0
    LURCH_TEST_RT="$RT" LURCH_TEST_CONTAINER="$CONTAINER_NAME" \
        "$HARNESS" --scenario "$scenario" ./build/lurch.so ./build/carbons.so || rc=$?

    dump_server_state
    reset_env

    if [ "$rc" -ne 0 ]; then
        failed+=("$scenario")
    fi
done

echo ""
echo "================ summary ================"
echo "ran:    ${scenarios[*]}"
if [ ${#failed[@]} -gt 0 ]; then
    echo "failed: ${failed[*]}"
    exit 1
fi
echo "all scenarios passed"
