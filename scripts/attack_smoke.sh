#!/usr/bin/env bash
# Black-box checks against a running deployment, using the seeded "eve" account
# (a viewer with no grants). Every line should print 404 / 401 / 403.
#   ./scripts/attack_smoke.sh https://your-app.onrender.com <document-id-owned-by-alice>
set -euo pipefail
BASE="${1:?base url}"; DOC="${2:?a document id eve was not granted}"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
CSRF=$(curl -s -c "$JAR" -H 'Content-Type: application/json' \
  -d '{"email":"eve@trustvault.demo","password":"Eve#Vault2026!"}' "$BASE/api/auth/login" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrf_token"])')
h=(-s -o /dev/null -w '%{http_code}\n' -b "$JAR" -H "X-CSRF-Token: $CSRF")
echo -n "metadata:            "; curl "${h[@]}" "$BASE/api/documents/$DOC"
echo -n "download:            "; curl "${h[@]}" -X POST "$BASE/api/documents/$DOC/download"
echo -n "old version:         "; curl "${h[@]}" -X POST "$BASE/api/documents/$DOC/versions/1/download"
echo -n "self-grant:          "; curl "${h[@]}" -H 'Content-Type: application/json' -d '{"email":"eve@trustvault.demo","permission":"edit"}' "$BASE/api/documents/$DOC/grants"
echo -n "rename:              "; curl "${h[@]}" -X PATCH -H 'Content-Type: application/json' -d '{"name":"x"}' "$BASE/api/documents/$DOC"
echo -n "delete:              "; curl "${h[@]}" -X DELETE "$BASE/api/documents/$DOC"
echo -n "share link:          "; curl "${h[@]}" -H 'Content-Type: application/json' -d '{"expires_hours":1}' "$BASE/api/documents/$DOC/shares"
echo -n "admin audit:         "; curl "${h[@]}" "$BASE/api/admin/audit"
echo -n "no CSRF token:       "; curl -s -o /dev/null -w '%{http_code}\n' -b "$JAR" -X POST "$BASE/api/documents/$DOC/download"
echo -n "malformed id:        "; curl "${h[@]}" "$BASE/api/documents/1%20OR%201=1"
echo -n "no session:          "; curl -s -o /dev/null -w '%{http_code}\n' "$BASE/api/documents/$DOC"
