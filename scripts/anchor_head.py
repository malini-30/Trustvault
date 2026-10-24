"""Publish the audit chain head outside the database.

The triggers stop the application (and anyone using its database login) from
altering audit rows, and the hash chain makes any alteration detectable. What the
chain cannot stop on its own is someone with full database control rewriting the
whole chain consistently. Recording the head somewhere they do not control closes
that: a rewritten chain will not end in a head you previously recorded.

Usage (prints one JSON line; append it to a file in another repository, a
write-once bucket, or e-mail it to yourself, on a schedule):

    TRUSTVAULT_URL=https://your-app.onrender.com ADMIN_EMAIL=... ADMIN_PASSWORD=... \
        python scripts/anchor_head.py >> anchors.jsonl

To check later that history was not rewritten, verify that each recorded
(head_id, head_hash) still appears in the audit trail with the same hash.
"""
import json
import os
import sys
from datetime import datetime, timezone

import requests

base = os.environ.get("TRUSTVAULT_URL", "http://localhost:5000").rstrip("/")
s = requests.Session()
login = s.post(f"{base}/api/auth/login", json={"email": os.environ["ADMIN_EMAIL"],
                                               "password": os.environ["ADMIN_PASSWORD"]}, timeout=60)
login.raise_for_status()
head = s.get(f"{base}/api/admin/audit/head", timeout=30)
head.raise_for_status()
verify = s.get(f"{base}/api/admin/audit/verify", timeout=120).json()
record = {"recorded_at": datetime.now(timezone.utc).isoformat(), "url": base, **head.json(),
          "chain_ok": verify.get("ok")}
print(json.dumps(record))
s.post(f"{base}/api/auth/logout", headers={"X-CSRF-Token": login.json()["csrf_token"]}, timeout=30)
sys.exit(0 if verify.get("ok") else 2)
