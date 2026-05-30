#!/bin/bash

# Configuration
DIR="rules"
SNAPSHOT="database/all_configs_snapshot.json"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"
BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"

mkdir -p "./$DIR"

# Cleanup on exit
trap "rm -f $BLOCK_TMP $ALLOW_TMP; exit" INT TERM EXIT

# Helper to extract and normalize domains
extract_domains() {
  awk '{
    if (/^[[:space:]]*$/ || /^[!#]/) next
    line = tolower($0)
    sub(/^@@\|\|?/, "", line)
    sub(/^\|\|?/, "", line)
    sub(/\^.*/, "", line)
    sub(/[#!].*/, "", line)
    sub(/\/.*/, "", line)
    sub(/:.*/, "", line)
    sub(/^[0-9.]+[[:space:]]+/, "", line)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/ && !seen[line]++) print line
  }'
}

# 1. Process Blocklists
echo "Processing blocklists..."
{
  if [ -f "$SNAPSHOT" ]; then
    # Download domains from all subscription URLs
    jq -r '.urls.blocklist[]' "$SNAPSHOT" 2>/dev/null | xargs -r curl -fsSL --max-time 60
    # Append custom blocklist domains
    jq -r '.custom_lists.blocklist' "$SNAPSHOT" 2>/dev/null
  fi
} | extract_domains > "$BLOCK_TMP"

# 2. Process Allowlists
echo "Processing allowlists..."
{
  if [ -f "$SNAPSHOT" ]; then
    # Download domains from all subscription URLs
    jq -r '.urls.allowlist[]' "$SNAPSHOT" 2>/dev/null | xargs -r curl -fsSL --max-time 60
    # Append custom allowlist domains
    jq -r '.custom_lists.allowlist' "$SNAPSHOT" 2>/dev/null
  fi
} | extract_domains > "$ALLOW_TMP"

# Move to final location
mv "$BLOCK_TMP" "$BLOCK_OUT"
mv "$ALLOW_TMP" "$ALLOW_OUT"

echo "Done. Files saved to $BLOCK_OUT and $ALLOW_OUT"

# Generate statistics
BLOCK_COUNT=$(wc -l < "$BLOCK_OUT" | tr -d ' ' || echo 0)
ALLOW_COUNT=$(wc -l < "$ALLOW_OUT" | tr -d ' ' || echo 0)

cat <<EOF > database/stats.json
{
  "blocklistSize": ${BLOCK_COUNT:-0},
  "allowlistSize": ${ALLOW_COUNT:-0},
  "_updated": $(date +%s%3N)
}
EOF
