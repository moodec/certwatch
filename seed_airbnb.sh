#!/usr/bin/env bash
# Run subfinder against all in-scope Airbnb root domains (excluding airbnb.com,
# which is already done) and seed certwatch's seen-domains store.
set -euo pipefail

RESULTS_DIR="/tmp/subfinder_results"
SEEN_DB="${HOME}/.local/share/certwatch/seen_domains.txt"
CERTWATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTWATCH="${CERTWATCH_DIR}/.venv/bin/certwatch"

mkdir -p "$RESULTS_DIR"

DOMAINS=(
  airbnbcitizen.com
  atairbnb.com
  withairbnb.com
  byairbnb.com
  muscache.com
  airbnb-aws.com
  luxuryretreats.com
  hoteltonight.com
  hoteltonight-test.com
  airbnb.org
  musta.ch
  airbnbpayments.com
)

for domain in "${DOMAINS[@]}"; do
  slug="${domain//./_}"
  outfile="${RESULTS_DIR}/${slug}_subfinder"
  echo "[*] Running subfinder for ${domain} -> ${outfile}"
  subfinder -d "$domain" -silent -o "$outfile"
  echo "    $(wc -l < "$outfile") subdomains found"
done

echo ""
echo "[*] Seeding certwatch with all results (including existing airbnb.com file)..."
cat "${RESULTS_DIR}"/*_subfinder | "$CERTWATCH" seed --seen-db "$SEEN_DB"
