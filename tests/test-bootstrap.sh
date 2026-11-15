#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash -n bootstrap.sh
out=$(bash bootstrap.sh --panel https://panel.example.org --domain sub.example.org --path /s --dry-run)
[[ "$out" == *'arguments: OK'* ]]
for wrong in \
 '--panel http://panel.example.org --domain sub.example.org --path /s' \
 '--panel https://panel.example.org:443 --domain sub.example.org --path /s' \
 '--panel https://panel.example.org --domain panel.example.org --path /s' \
 '--panel https://panel.example.org --domain sub.example.org --path /api/v1' \
 '--panel https://panel.example.org --domain sub.example.org --path /s/../admin'; do
 # This test intentionally expands only a controlled list of invalid flags.
 # shellcheck disable=SC2086
 if bash bootstrap.sh $wrong --dry-run >/dev/null 2>&1; then
  echo "bootstrap accepted invalid arguments" >&2; exit 1
 fi
done
grep -Fq 'read -r -s ENROLL_TOKEN </dev/tty' bootstrap.sh
grep -Fq -- '--enroll-token-stdin' bootstrap.sh
# shellcheck disable=SC2016 # literal source assertion
grep -Fq -- '--source-digest "$sha"' bootstrap.sh
grep -Fq -- '--cert-identity' bootstrap.sh
grep -Fq -- '--deny-self-hosted-runners' bootstrap.sh
grep -Fq "sha256sum --check --status" bootstrap.sh
# shellcheck disable=SC2016 # literal source assertion
if grep -Fq -- '--enroll-token "$ENROLL_TOKEN"' bootstrap.sh; then echo 'Credential leaked into argv' >&2; exit 1; fi
if grep -Fq 'gh auth login' bootstrap.sh; then echo 'Interactive GitHub authentication forbidden' >&2; exit 1; fi
echo 'Immutable short bootstrap, TTY-only enrollment and OIDC checks passed'
