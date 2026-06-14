#!/bin/bash
# update_lists.sh
# ─────────────────────────────────────────────────────────────────────────────
# Fetches and merges all external DNS blocklist/allowlist subscriptions.
# Reads URL sources from:  database/all_configs_snapshot.json
# Writes merged output to: rules/blocklists.txt and rules/allowlists.txt
#
# Supported list formats: AdBlock/ABP (||domain^), hosts files (0.0.0.0 domain),
#                          plain domain lists (one domain per line).
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

DIR="rules"
SNAPSHOT="database/all_configs_snapshot.json"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"
BLOCK_TMP=$(mktemp /tmp/blocklists.XXXXXX)
ALLOW_TMP=$(mktemp /tmp/allowlists.XXXXXX)
DB_DIR="database"

mkdir -p "./$DIR" "./$DB_DIR"

# Cleanup temp files on exit
trap "rm -f '$BLOCK_TMP' '$ALLOW_TMP'" EXIT INT TERM

# ─────────────────────────────────────────────────────────────────────────────
# Helper: normalize and extract valid domains from any list format
# ─────────────────────────────────────────────────────────────────────────────
extract_domains() {
  awk '
  {
    # Skip blank lines and comment lines
    if (/^[[:space:]]*$/ || /^[[:space:]]*[#!]/) next

    line = tolower($0)

    # Allowlist ABP format (@@||domain^)
    if (line ~ /^@@\|\|/) {
      sub(/^@@\|\|/, "", line)
    }
    # ABP format (||domain^)
    else if (line ~ /^\|\|?/) {
      sub(/^\|\|?/, "", line)
    }
    # Hosts file format (0.0.0.0 domain or 127.0.0.1 domain)
    else if (line ~ /^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]/) {
      sub(/^[0-9.]+[[:space:]]+/, "", line)
    }

    # Strip modifiers and trailing anchors
    sub(/\^.*$/, "", line)
    sub(/[#!].*$/, "", line)
    sub(/\/.*$/, "", line)
    sub(/:.*$/, "", line)

    # Strip leading/trailing whitespace
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

    # Skip localhost entries
    if (line == "localhost" || line == "0.0.0.0" || line == "127.0.0.1") next

    # Only emit valid domain names
    if (line ~ /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/ && !seen[line]++) {
      print line
    }
  }'
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper: fetch a URL with retries and a timeout
# ─────────────────────────────────────────────────────────────────────────────
fetch_url() {
  local url="$1"
  local name="${2:-list}"
  echo "  → Fetching: $name" >&2
  curl -fsSL --max-time 60 --retry 2 --retry-delay 3 \
       -H "User-Agent: edge-dns-gateway/2.0 update_lists.sh" \
       "$url" 2>/dev/null || {
    echo "  ⚠ Failed to fetch: $url" >&2
    return 0  # Non-fatal: continue with other lists
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Load snapshot config
# ─────────────────────────────────────────────────────────────────────────────
if [ ! -f "$SNAPSHOT" ]; then
  echo "⚠ Snapshot not found: $SNAPSHOT — no lists to fetch." >&2
  exit 0
fi

echo "🔄 Reading config from: $SNAPSHOT"

# ─────────────────────────────────────────────────────────────────────────────
# 2. Process Blocklists
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "📥 Processing blocklists..."
{
  # External subscription URLs
  mapfile -t BLOCK_URLS < <(jq -r '.urls.blocklist[]? // empty' "$SNAPSHOT" 2>/dev/null)
  for url in "${BLOCK_URLS[@]}"; do
    fetch_url "$url" "$(basename "$url")"
  done

  # Inline custom domains from snapshot
  jq -r '.custom_lists.blocklist // ""' "$SNAPSHOT" 2>/dev/null
} | extract_domains | sort -u > "$BLOCK_TMP"

BLOCK_COUNT=$(wc -l < "$BLOCK_TMP" | tr -d ' ')
echo "  ✅ Blocklist: $BLOCK_COUNT domains"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Process Allowlists
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "📥 Processing allowlists..."
{
  # External subscription URLs
  mapfile -t ALLOW_URLS < <(jq -r '.urls.allowlist[]? // empty' "$SNAPSHOT" 2>/dev/null)
  for url in "${ALLOW_URLS[@]}"; do
    fetch_url "$url" "$(basename "$url")"
  done

  # Inline custom domains from snapshot
  jq -r '.custom_lists.allowlist // ""' "$SNAPSHOT" 2>/dev/null
} | extract_domains | sort -u > "$ALLOW_TMP"

ALLOW_COUNT=$(wc -l < "$ALLOW_TMP" | tr -d ' ')
echo "  ✅ Allowlist: $ALLOW_COUNT domains"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Move output to final location
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "💾 Writing output files..."
mv "$BLOCK_TMP" "$BLOCK_OUT"
mv "$ALLOW_TMP" "$ALLOW_OUT"

echo "  ✅ $BLOCK_OUT"
echo "  ✅ $ALLOW_OUT"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Write updated stats.json
# ─────────────────────────────────────────────────────────────────────────────
UPDATED_MS=$(date +%s%3N 2>/dev/null || echo "0")
cat > "$DB_DIR/stats.json" <<EOF
{
  "blocklistSize": ${BLOCK_COUNT},
  "allowlistSize": ${ALLOW_COUNT},
  "_updated": ${UPDATED_MS}
}
EOF
echo "  ✅ $DB_DIR/stats.json"

echo ""
echo "✅ Done — blocklist: $BLOCK_COUNT, allowlist: $ALLOW_COUNT domains"
