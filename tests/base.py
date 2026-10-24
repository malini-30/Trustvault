"""Shared fixtures. Integration tests need a real PostgreSQL database the test
user OWNS but is NOT a superuser of (superusers bypass row-level security, which
would make half of these tests meaningless). Point TEST_DATABASE_URL at it:

    createdb trustvault_test
    TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/trustvault_test python -m unittest -v

Every test starts from an empty schema, migrated from scratch.

The fixture world:
    alice (owner)  owns DOC_A  -> victor has READ, edna has EDIT
    bob   (owner)  owns DOC_B  -> no grants
    eve   (viewer) holds nothing at all
    admin (admin)  holds nothing at all
"""
import io
import os
import unittest
from unittest import mock

from app import create_app, security
from app.config import Config
from app.db import Database
from app.migrate import migrate

TEST_DB = os.environ.get("TEST_DATABASE_URL", "")
PASSWORD = "Correct-Horse-9"


def require_db(cls):
    return unittest.skipUnless(TEST_DB, "set TEST_DATABASE_URL to run integration tests")(cls)


class Client:
    """A signed-in browser: session cookie plus the CSRF token for that session."""

    def __init__(self, app, email=None, password=PASSWORD):
        self.http = app.test_client()
        self.csrf = None
        self.user = None
        if email:
            r = self.http.post("/api/auth/login", json={"email": email, "password": password})
            assert r.status_code == 200, (email, r.status_code, r.get_json())
            body = r.get_json()
            self.csrf, self.user = body["csrf_token"], body["user"]

    def _h(self, extra=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def get(self, url, **kw):
        return self.http.get(url, headers=self._h(kw.pop("headers", None)), **kw)

    def post(self, url, **kw):
        return self.http.post(url, headers=self._h(kw.pop("headers", None)), **kw)

    def patch(self, url, **kw):
        return self.http.patch(url, headers=self._h(kw.pop("headers", None)), **kw)

    def delete(self, url, **kw):
        return self.http.delete(url, headers=self._h(kw.pop("headers", None)), **kw)

    def upload(self, url, filename, data, **fields):
        form = {"file": (io.BytesIO(data), filename), **fields}
        return self.post(url, data=form, content_type="multipart/form-data")


class IntegrationTest(unittest.TestCase):
    MODE = "both"  # "both" | "app_only" | "rls_only"

    @classmethod
    def setUpClass(cls):
        if not TEST_DB:
            raise unittest.SkipTest("set TEST_DATABASE_URL to run integration tests")

    def setUp(self):
        migrate(TEST_DB, reset=True)
        security.limiter.reset()
        self.app = create_app(Config(DATABASE_URL=TEST_DB, TESTING=True, COOKIE_SECURE=False,
                                     TRUST_PROXY_HOPS=0, STORAGE_BACKEND="db",
                                     MASTER_KEY="test-master-key-0123456789", SECRET_KEY="test-secret-key-0123456789"))
        self.db = Database(TEST_DB)
        self._build_world()
        self._apply_mode()

    def tearDown(self):
        for p in getattr(self, "_patches", []):
            p.stop()
        self.db.close()
        if self.MODE == "app_only":
            self._set_force(True)

    # ------------------------------------------------------------- modes
    RLS_TABLES = ("documents", "document_versions", "grants", "share_links", "blobs", "ai_suggestions")

    def _set_force(self, on: bool):
        d = Database(TEST_DB)
        d.set_context(system=True)
        for t in self.RLS_TABLES:
            d.run(f"ALTER TABLE {t} {'FORCE' if on else 'NO FORCE'} ROW LEVEL SECURITY")
        d.commit()
        d.close()

    def _apply_mode(self):
        self._patches = []
        if self.MODE == "app_only":
            # Turn the database lock off (the table owner bypasses RLS without FORCE):
            # whatever still holds is held by the application's authorize() alone.
            self._set_force(False)
        elif self.MODE == "rls_only":
            # Take the application's decision out, as if the check line were deleted:
            # whatever still holds is held by the database alone.
            self._patches = [
                mock.patch("app.authz.decide", lambda subject, doc, grant, action: doc is not None),
                mock.patch("app.services.shares.decide_share", lambda link, doc, now=None: link is not None and doc is not None),
            ]
            for p in self._patches:
                p.start()

    # ------------------------------------------------------------ fixtures
    def _build_world(self):
        from app.services import documents, grants

        with self.app.test_request_context("/fixture"):
            from app import get_db

            db = get_db()
            db.set_context(system=True)
            self.users = {}
            for name, role in (("admin", "admin"), ("alice", "owner"), ("bob", "owner"), ("victor", "viewer"),
                               ("edna", "viewer"), ("eve", "viewer")):
                self.users[name] = db.one(
                    "INSERT INTO users (email, full_name, role, password_hash) VALUES (%s, %s, %s, %s) "
                    "RETURNING id, email, full_name, role, is_active",
                    (f"{name}@test.example", name.title(), role, security.hash_password(PASSWORD)))
            db.commit()
            alice, bob = self.users["alice"], self.users["bob"]
            db.set_context(user_id=alice["id"], role="owner")
            self.doc_a = documents.create(db, alice, "salary-alice.txt", b"Alice's salary letter v1\n",
                                          "Salary letter", "HR")["id"]
            grants.grant(db, alice, self.doc_a, "victor@test.example", "read")
            grants.grant(db, alice, self.doc_a, "edna@test.example", "edit")
            db.commit()
            db.set_context(user_id=bob["id"], role="owner")
            self.doc_b = documents.create(db, bob, "contract-bob.txt", b"Bob's contract\n", "Bob contract",
                                          "Legal")["id"]
            db.commit()

    def login(self, name) -> Client:
        return Client(self.app, f"{name}@test.example")

    def anon(self) -> Client:
        return Client(self.app)

    # ------------------------------------------------------------ helpers
    def sql(self, query, params=None, system=True):
        d = Database(TEST_DB)
        d.set_context(system=system)
        try:
            return d.all(query, params)
        finally:
            d.rollback()
            d.close()

    def audit_rows(self, action=None, actor=None):
        rows = self.sql("SELECT * FROM audit_events ORDER BY id")
        if action:
            rows = [r for r in rows if r["action"] == action]
        if actor:
            rows = [r for r in rows if r["actor_email"] == f"{actor}@test.example"]
        return rows

    def assertDenied(self, resp, msg=None, empty_key=None, own_user=None):
        """404 is the only acceptable answer to an unauthorised request. In
        rls_only mode a listing endpoint may instead answer with an empty list (or
        only the caller's own row): the database returned nothing, nothing leaked."""
        if resp.status_code == 404:
            return
        if self.MODE == "rls_only" and empty_key and resp.status_code in (200, 201):
            items = (resp.get_json() or {}).get(empty_key) or []
            if own_user:
                items = [i for i in items if i.get("user_id") != own_user]
            if not items:
                return
        self.fail(f"{msg or ''}: expected 404, got {resp.status_code} {resp.get_data(as_text=True)[:200]}")
