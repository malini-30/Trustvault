"""Lock B on its own: raw SQL against the database with no application code in
the way. These are the queries a bug in the application (a forgotten check, a
bad join, an injected filter) would run, and the database refuses them."""
from datetime import datetime, timedelta, timezone

from app.db import Database, DbError
from app.security import sha256_hex

from .base import TEST_DB, IntegrationTest, require_db


@require_db
class RowLevelSecurity(IntegrationTest):
    def as_user(self, name) -> Database:
        d = Database(TEST_DB)
        u = self.users[name]
        d.set_context(user_id=u["id"], role=u["role"])
        self.addCleanup(d.close)
        return d

    def assertRefused(self, d, sql, params=None):
        with self.assertRaises(DbError) as ctx:
            d.run(sql, params)
        d.rollback()
        self.assertIn(getattr(ctx.exception, "sqlstate", None), ("42501", "23514"))

    def test_outsider_sees_no_rows_even_with_unfiltered_queries(self):
        d = self.as_user("eve")
        for table in ("documents", "document_versions", "grants", "share_links", "blobs", "ai_suggestions"):
            self.assertEqual(d.all(f"SELECT * FROM {table}"), [], table)

    def test_each_user_sees_exactly_their_documents(self):
        expect = {"alice": {self.doc_a}, "bob": {self.doc_b}, "victor": {self.doc_a}, "edna": {self.doc_a}}
        for name, docs in expect.items():
            got = {r["id"] for r in self.as_user(name).all("SELECT id FROM documents")}
            self.assertEqual(got, docs, name)

    def test_anonymous_context_sees_nothing(self):
        d = Database(TEST_DB)
        self.addCleanup(d.close)
        self.assertEqual(d.all("SELECT * FROM documents"), [])
        self.assertEqual(d.all("SELECT * FROM blobs"), [])

    def test_admin_sees_metadata_but_never_keys_or_bytes(self):
        d = self.as_user("admin")
        self.assertEqual(len(d.all("SELECT id FROM documents")), 2)
        self.assertEqual(d.all("SELECT storage_key, wrapped_key FROM document_versions"), [])
        self.assertEqual(d.all("SELECT data FROM blobs"), [])

    def test_grantee_cannot_reach_other_peoples_grant_rows(self):
        rows = self.as_user("victor").all("SELECT user_id FROM grants")
        self.assertEqual({r["user_id"] for r in rows}, {self.users["victor"]["id"]})

    def test_nobody_but_the_owner_can_grant(self):
        for name in ("eve", "victor", "edna", "admin", "bob"):
            d = self.as_user(name)
            self.assertRefused(d, "INSERT INTO grants (document_id, user_id, owner_id, permission, granted_by) "
                                  "VALUES (%s, %s, %s, 'edit', %s)",
                               (self.doc_a, self.users["eve"]["id"], self.users["alice"]["id"], self.users[name]["id"]))

    def test_forged_owner_id_on_a_grant_is_overwritten(self):
        # Edna (editor) claims to be the owner in the row she inserts: the trigger
        # replaces owner_id with the real owner and the policy then refuses.
        d = self.as_user("edna")
        self.assertRefused(d, "INSERT INTO grants (document_id, user_id, owner_id, permission, granted_by) "
                              "VALUES (%s, %s, %s, 'read', %s)",
                           (self.doc_a, self.users["eve"]["id"], self.users["edna"]["id"], self.users["edna"]["id"]))

    def test_reader_updates_match_zero_rows(self):
        d = self.as_user("victor")
        self.assertEqual(d.run("UPDATE documents SET name = 'x' WHERE id = %s", (self.doc_a,)), 0)
        self.assertEqual(d.run("DELETE FROM documents WHERE id = %s", (self.doc_a,)), 0)

    def test_editor_cannot_delete_or_take_ownership(self):
        d = self.as_user("edna")
        self.assertRefused(d, "UPDATE documents SET deleted_at = now() WHERE id = %s", (self.doc_a,))
        self.assertRefused(d, "UPDATE documents SET owner_id = %s WHERE id = %s", (self.users["edna"]["id"], self.doc_a))
        self.assertEqual(d.run("UPDATE documents SET name = 'ok by editor' WHERE id = %s", (self.doc_a,)), 1)

    def test_guard_trigger_blocks_what_policies_cannot_express(self):
        # Setting deleted_by leaves the row visible, so the SELECT policy alone would
        # allow it; only the column guard trigger refuses an editor touching it.
        d = self.as_user("edna")
        self.assertRefused(d, "UPDATE documents SET deleted_by = %s WHERE id = %s", (self.users["edna"]["id"], self.doc_a))

    def test_owner_cannot_give_a_document_away_or_create_one_for_someone_else(self):
        d = self.as_user("alice")
        self.assertRefused(d, "UPDATE documents SET owner_id = %s WHERE id = %s", (self.users["bob"]["id"], self.doc_a))
        self.assertRefused(d, "INSERT INTO documents (owner_id, name, category, mime, size_bytes) "
                              "VALUES (%s, 'planted', 'HR', 'text/plain', 1)", (self.users["bob"]["id"],))

    def test_viewer_cannot_create_documents(self):
        d = self.as_user("eve")
        self.assertRefused(d, "INSERT INTO documents (owner_id, name, category, mime, size_bytes) "
                              "VALUES (%s, 'mine', 'HR', 'text/plain', 1)", (self.users["eve"]["id"],))

    def test_content_of_a_trashed_document_is_hidden_even_from_its_owner(self):
        d = self.as_user("alice")
        d.run("UPDATE documents SET deleted_at = now() WHERE id = %s", (self.doc_a,))
        self.assertEqual(d.all("SELECT 1 FROM document_versions WHERE document_id = %s", (self.doc_a,)), [])
        self.assertEqual(d.all("SELECT 1 FROM blobs"), [])
        d.rollback()

    def _make_link(self, **overrides):
        token = "T" * 43
        d = Database(TEST_DB)
        d.set_context(system=True)
        row = d.one("INSERT INTO share_links (document_id, owner_id, token_hash, created_by, expires_at, max_downloads) "
                    "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                    (self.doc_a, self.users["alice"]["id"], sha256_hex(token), self.users["alice"]["id"],
                     overrides.get("expires_at", datetime.now(timezone.utc) + timedelta(hours=1)),
                     overrides.get("max_downloads")))
        d.commit()
        d.close()
        return token, row["id"]

    def test_share_token_context_sees_only_its_own_document(self):
        token, _ = self._make_link()
        d = Database(TEST_DB)
        self.addCleanup(d.close)
        d.set_context(share_hash=sha256_hex(token))
        self.assertEqual({r["id"] for r in d.all("SELECT id FROM documents")}, {self.doc_a})
        self.assertEqual(len(d.all("SELECT 1 FROM document_versions")), 1)
        self.assertEqual(d.all("SELECT 1 FROM grants"), [])
        d.set_context(share_hash=sha256_hex("wrong" * 9))
        self.assertEqual(d.all("SELECT id FROM documents"), [])

    def test_token_holder_cannot_extend_unrevoke_or_reset_a_link(self):
        token, link_id = self._make_link(max_downloads=1)
        d = Database(TEST_DB)
        self.addCleanup(d.close)
        d.set_context(share_hash=sha256_hex(token))
        self.assertRefused(d, "UPDATE share_links SET expires_at = expires_at + interval '1 year' WHERE id = %s", (link_id,))
        d.set_context(share_hash=sha256_hex(token))
        self.assertRefused(d, "UPDATE share_links SET download_count = 0, max_downloads = 999 WHERE id = %s", (link_id,))
        d.set_context(share_hash=sha256_hex(token))
        self.assertEqual(d.run("UPDATE share_links SET download_count = download_count + 1 WHERE id = %s", (link_id,)), 1)
        d.commit()
        d.set_context(share_hash=sha256_hex(token))
        self.assertRefused(d, "UPDATE share_links SET download_count = 0 WHERE id = %s", (link_id,))
        d.set_context(share_hash=sha256_hex(token))
        self.assertEqual(d.all("SELECT id FROM documents"), [], "used-up link opens nothing")

    def test_owner_cannot_unrevoke_a_link(self):
        _, link_id = self._make_link()
        d = self.as_user("alice")
        d.run("UPDATE share_links SET revoked_at = now() WHERE id = %s", (link_id,))
        d.commit()
        d.set_context(user_id=self.users["alice"]["id"], role="owner")
        self.assertRefused(d, "UPDATE share_links SET revoked_at = NULL WHERE id = %s", (link_id,))

    def test_rls_is_forced_on_every_protected_table(self):
        rows = self.sql("SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = ANY(%s::text[])",
                        (list(self.RLS_TABLES),))
        self.assertEqual(len(rows), len(self.RLS_TABLES))
        for r in rows:
            self.assertTrue(r["relrowsecurity"] and r["relforcerowsecurity"], r["relname"])

    def test_the_application_user_is_not_a_superuser(self):
        # A superuser bypasses RLS entirely; if this ever fails, lock B is gone.
        self.assertFalse(self.sql("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")[0]["rolsuper"])
