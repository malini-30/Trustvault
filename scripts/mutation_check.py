"""Remove authorization checks one at a time and prove the tests notice.

This is what the judges will do by hand ("take one authorisation check out and
run your tests"), done for every check. Each mutation edits one file in place,
runs the whole suite (fail-fast), and restores the file whatever happens.
A mutation that SURVIVES (tests still pass) means a check is not tested.

    TEST_DATABASE_URL=postgresql://... python scripts/mutation_check.py
"""
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent

MUTATIONS = [
    # --- Lock A: the application's decision -------------------------------
    ("app/authz.py", 'return is_owner or grant_permission in ("read", "edit")', "return True",
     "decide(): anyone may READ"),
    ("app/authz.py", 'return is_owner or grant_permission == "edit"',
     'return is_owner or grant_permission in ("read", "edit")', "decide(): readers may EDIT"),
    ("app/authz.py", "if action in (Action.DELETE, Action.MANAGE):\n        return is_owner",
     'if action in (Action.DELETE, Action.MANAGE):\n        return is_owner or grant_permission == "edit"',
     "decide(): editors may delete / manage grants"),
    ("app/authz.py", "    if deleted:\n        return False", "    if False:\n        return False",
     "decide(): deleted documents stay reachable"),
    ("app/authz.py", "if subject is None or not subject.is_active:", "if subject is None:",
     "decide(): deactivated users allowed"),
    ("app/authz.py", "    if not decide(subject, doc, grant, action):", "    if doc is None:",
     "authorize(): decision removed entirely"),
    ("app/authz.py", '    if link.get("revoked_at") is not None:\n        return False', "",
     "decide_share(): revoked links work"),
    ("app/authz.py", '    if link["expires_at"] <= now:\n        return False', "",
     "decide_share(): expired links work"),
    ("app/authz.py",
     '    if link.get("max_downloads") is not None and link["download_count"] >= link["max_downloads"]:\n        return False',
     "", "decide_share(): download cap ignored"),
    ("app/services/documents.py", "    doc = authorize(db, user, doc_id, Action.READ)\n    if version is None:",
     '    doc = db.one(f"SELECT {DOC_COLUMNS} FROM documents WHERE id = %s", (doc_id,))\n'
     '    doc["my_permission"] = "?"\n    if version is None:',
     "download(): the authorize() line deleted (the interview question)"),
    ("app/services/grants.py",
     "def grant(db, user: dict, doc_id, email, permission, via=\"manual\", suggestion_id=None) -> dict:\n"
     "    doc = authorize(db, user, doc_id, Action.MANAGE)",
     "def grant(db, user: dict, doc_id, email, permission, via=\"manual\", suggestion_id=None) -> dict:\n"
     "    doc = authorize(db, user, doc_id, Action.READ)",
     "grant(): readers may grant onward"),
    ("app/services/documents.py", '"AND g.user_id = %s))")', '"OR g.user_id <> %s))")',
     "search(): visibility filter widened"),
    ("app/services/users.py", 'if user is None or user.get("role") != "admin":', "if user is None:",
     "services: admin role check removed"),
    ("app/web/common.py", '        if g.user["role"] != "admin":\n            raise Forbidden()', "",
     "routes: admin decorator check removed"),
    # --- Lock B: the database ---------------------------------------------
    ("migrations/002_rls.sql", "            OR tv_has_grant(id, 'read')\n", "            OR true\n",
     "RLS documents_select: everyone sees live documents"),
    ("migrations/002_rls.sql", "AND (d.owner_id = tv_uid() OR tv_has_grant(d.id, 'read') OR tv_share_allows(d.id)))",
     "AND (d.owner_id = tv_uid() OR tv_has_grant(d.id, 'read') OR tv_share_allows(d.id) OR tv_role() = 'admin'))",
     "RLS versions_select: admins reach content"),
    ("migrations/002_rls.sql",
     "CREATE POLICY grants_insert ON grants FOR INSERT WITH CHECK (tv_system() OR owner_id = tv_uid());",
     "CREATE POLICY grants_insert ON grants FOR INSERT WITH CHECK (true);", "RLS grants_insert: anyone grants"),
    ("migrations/002_rls.sql", "ALTER TABLE documents FORCE ROW LEVEL SECURITY;", "",
     "RLS not FORCEd on documents (owner bypass)"),
    ("migrations/002_rls.sql",
     "    IF OLD.owner_id IS DISTINCT FROM tv_uid()\n       AND (NEW.deleted_at",
     "    IF false\n       AND (NEW.deleted_at", "guard trigger: editors may delete"),
    ("migrations/002_rls.sql", "        IF NEW.download_count <> OLD.download_count + 1\n",
     "        IF false\n", "guard trigger: token holder may reset/extend links"),
    # --- Audit, sessions, CSRF, uploads -----------------------------------
    ("migrations/003_audit_protection.sql", "CREATE TRIGGER audit_no_update_delete", "CREATE TRIGGER audit_no_update_delete_off BEFORE UPDATE ON schema_migrations FOR EACH ROW EXECUTE FUNCTION tv_audit_immutable();\n-- ",
     "audit rows become editable"),
    ("app/audit.py", '        if compute_hash(row) != row["hash"]:', "        if False:",
     "audit verify ignores altered rows"),
    ("app/audit.py", '        if row["prev_hash"] != prev:', "        if False:", "audit verify ignores removed rows"),
    ("app/authz.py", "        audit.deny(db, \"access_denied\"", "        (lambda *a, **k: None)(db, \"access_denied\"",
     "refusals are no longer audited"),
    ("app/services/users.py", 'if not row["is_active"] or row["expires_at"]', 'if row["expires_at"]',
     "sessions of deactivated users keep working"),
    ("app/services/users.py", "    ended = end_all_sessions(db, user_id)\n    action =",
     "    ended = 0\n    action =", "role change / deactivation leaves sessions alive"),
    ("app/__init__.py", 'if not security.tokens_equal(sent, g.session["csrf_token"]):', "if False:",
     "CSRF check disabled"),
    ("app/validation.py", "    if actual != expected:", "    if False:", "upload type check disabled"),
    ("app/services/shares.py", '"WHERE id = %s AND download_count = %s"', '"WHERE id = %s AND %s IS NOT NULL"',
     "share counter compare-and-set removed (race on the last download)"),
]


def run_tests(env) -> bool:
    proc = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-f", "-q"],
                          cwd=ROOT, env=env, capture_output=True, text=True)
    return proc.returncode == 0


def main() -> int:
    if not os.environ.get("TEST_DATABASE_URL"):
        sys.exit("Set TEST_DATABASE_URL (see tests/base.py).")
    env = dict(os.environ)
    print("Baseline run ...", flush=True)
    if not run_tests(env):
        sys.exit("The unmutated suite fails; fix that first.")
    survivors = []
    for i, (rel, old, new, label) in enumerate(MUTATIONS, 1):
        path = ROOT / rel
        original = path.read_text()
        if original.count(old) != 1:
            print(f"[{i:02d}] SKIP  {label}  (pattern not found exactly once in {rel})")
            survivors.append((label, "pattern missing"))
            continue
        path.write_text(original.replace(old, new, 1))
        start = time.time()
        try:
            passed = run_tests(env)
        finally:
            path.write_text(original)
        verdict = "SURVIVED" if passed else "caught"
        print(f"[{i:02d}] {verdict:8s} {label}  ({time.time() - start:.0f}s)", flush=True)
        if passed:
            survivors.append((label, "tests still pass"))
    print(f"\n{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} mutations caught.")
    for label, why in survivors:
        print(f"  NOT CAUGHT: {label} ({why})")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
