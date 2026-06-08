#!/bin/bash
# ScanBoy Purge Script
# Usage:
#   bash scripts/purge.sh              — flush uploaded files + caches (keeps reports/analysis data)
#   bash scripts/purge.sh --all        — flush everything including analysis data
#   bash scripts/purge.sh --nuke       — flush everything including users

set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-files}"

echo "=== ScanBoy Purge (mode: $MODE) ==="
echo ""

if [[ "$MODE" == "--nuke" ]]; then
  echo "WARNING: --nuke will delete ALL data including users, sessions, and audit logs."
  read -p "Type 'yes' to confirm: " confirm
  [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 1; }
elif [[ "$MODE" == "--all" ]]; then
  echo "WARNING: --all will delete all submissions and analysis data."
  read -p "Type 'yes' to confirm: " confirm
  [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 1; }
fi

# 1. Flush scanboy Redis keys (preserve other data)
echo "[1/4] Flushing scanboy Redis keys..."
docker compose exec -T redis sh -c 'redis-cli --no-auth-warning -a "$REDIS_PASSWORD" --scan --pattern "scanboy:*" | xargs -r redis-cli --no-auth-warning -a "$REDIS_PASSWORD" DEL' 2>/dev/null && echo "  Redis scanboy keys flushed" || echo "  Redis not available"

# 2. Kill leftover sandbox containers
echo "[2/4] Cleaning sandbox containers..."
SANDBOX_CONTAINERS=$(docker ps -a --filter "name=scanboy-det-" -q 2>/dev/null)
if [[ -n "$SANDBOX_CONTAINERS" ]]; then
  docker rm -f $SANDBOX_CONTAINERS 2>/dev/null
  echo "  Removed $(echo "$SANDBOX_CONTAINERS" | wc -l) sandbox containers"
else
  echo "  No sandbox containers found"
fi

# 3. Clean temp files on host and in containers
echo "[3/4] Cleaning temp files..."
find /tmp -maxdepth 1 -name 'scanboy-*' -type d -exec rm -rf {} + 2>/dev/null
docker compose exec -T dynamic-analysis sh -c "find /tmp -maxdepth 1 -name 'scanboy-*' -type d -exec rm -rf {} + 2>/dev/null" 2>/dev/null || true
echo "  Temp files cleaned"

# 4. Conditionally clear database
if [[ "$MODE" == "--all" || "$MODE" == "--nuke" ]]; then
  echo "[4/4] Clearing all analysis data from PostgreSQL..."
  docker compose exec -T postgres psql -U scanboy -d scanboy -q << 'SQL'
DELETE FROM ioc_correlations;
DELETE FROM iocs;
DELETE FROM attack_techniques;
DELETE FROM generated_rules;
DELETE FROM yara_scan_results;
DELETE FROM memory_analysis_results;
DELETE FROM network_captures;
DELETE FROM dynamic_analysis_results;
DELETE FROM static_analysis_results;
DELETE FROM threat_intel_results;
DELETE FROM detonation_sessions;
DELETE FROM family_memberships;
DELETE FROM submission_notes;
DELETE FROM submission_tags;
DELETE FROM analysis_jobs;
DELETE FROM submissions;
SQL
  echo "  All submissions and analysis data cleared"

  if [[ "$MODE" == "--nuke" ]]; then
    echo "  Clearing users, sessions, audit logs..."
    docker compose exec -T postgres psql -U scanboy -d scanboy -q << 'SQL'
DELETE FROM audit_log;
DELETE FROM sessions;
DELETE FROM api_keys;
DELETE FROM users;
SQL
    echo "  All users and sessions cleared"
  fi
else
  echo "[4/4] Database: KEPT (reports and analysis data preserved)"
  echo "  Use --all to also clear analysis data"
fi

echo ""
echo "=== Purge complete ==="
echo ""
echo "What was cleaned:"
echo "  ✓ Redis (uploaded file buffers, PCAPs, temp caches)"
echo "  ✓ Sandbox containers (any leftover detonation containers)"
echo "  ✓ Temp files (host + container /tmp/scanboy-*)"
if [[ "$MODE" == "--all" || "$MODE" == "--nuke" ]]; then
  echo "  ✓ Database (all submissions, analysis, IOCs, ATT&CK, threat intel)"
fi
if [[ "$MODE" == "--nuke" ]]; then
  echo "  ✓ Users, sessions, audit logs"
fi
if [[ "$MODE" != "--all" && "$MODE" != "--nuke" ]]; then
  echo "  ✗ Database preserved (submissions, reports, IOCs, threat intel all intact)"
fi
