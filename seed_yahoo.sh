#!/usr/bin/env bash
# Seed certwatch's seen-domains store with existing Yahoo subdomains.
set -euo pipefail

RESULTS_DIR="/tmp/subfinder_results_yahoo"
SEEN_DB="${HOME}/.local/share/certwatch/seen_domains.txt"
CERTWATCH="${HOME}/Tools/certwatch/.venv/bin/certwatch"

mkdir -p "$RESULTS_DIR"

DOMAINS=(
  yahoo.com
  yimg.com
)

for domain in "${DOMAINS[@]}"; do
  slug="${domain//./_}"
  outfile="${RESULTS_DIR}/${slug}_subfinder"
  echo "[*] Running subfinder for ${domain} -> ${outfile}"
  subfinder -d "$domain" -silent -o "$outfile"
  echo "    $(wc -l < "$outfile") subdomains found"
done

echo ""
echo "[*] Seeding certwatch with all results..."
cat "${RESULTS_DIR}"/*_subfinder | "$CERTWATCH" seed --seen-db "$SEEN_DB"
