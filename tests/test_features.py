"""Functional requirements: search, versions, trash, AI suggestions, admin views."""
from datetime import date

from .base import IntegrationTest, require_db


@require_db
class SearchAndDocuments(IntegrationTest):
    def test_search_by_name_owner_category_and_date(self):
        alice = self.login("alice")
        alice.upload("/api/documents", "budget.csv", b"a,b\n1,2\n", name="Budget 2027", category="Finance")
        names = lambda q: sorted(d["name"] for d in alice.get("/api/documents" + q).get_json()["items"])  # noqa: E731
        self.assertEqual(names("?q=budget"), ["Budget 2027"])
        self.assertEqual(names("?category=HR"), ["Salary letter"])
        self.assertEqual(names("?owner=alice"), ["Budget 2027", "Salary letter"])
        today = date.today().isoformat()
        self.assertEqual(len(names(f"?from={today}&to={today}")), 2)
        self.assertEqual(names("?from=2000-01-01&to=2000-01-02"), [])
        self.assertEqual(alice.get("/api/documents?from=yesterday").status_code, 400)
        self.assertEqual(alice.get("/api/documents?category=Nope").status_code, 400)

    def test_wildcards_in_search_are_literal(self):
        alice = self.login("alice")
        self.assertEqual(alice.get("/api/documents?q=%25").get_json()["items"], [])
        self.assertEqual(alice.get("/api/documents?q=_").get_json()["items"], [])

    def test_shared_scope_and_permission_labels(self):
        edna = self.login("edna")
        items = edna.get("/api/documents?scope=shared").get_json()["items"]
        self.assertEqual([(i["name"], i["my_permission"]) for i in items], [("Salary letter", "edit")])

    def test_versions_are_kept_and_downloadable(self):
        alice, a = self.login("alice"), self.doc_a
        self.assertEqual(alice.upload(f"/api/documents/{a}/versions", "v2.txt", b"version two\n").status_code, 201)
        versions = alice.get(f"/api/documents/{a}/versions").get_json()["versions"]
        self.assertEqual([v["version"] for v in versions], [2, 1])
        self.assertEqual(alice.post(f"/api/documents/{a}/download").data, b"version two\n")
        self.assertEqual(alice.post(f"/api/documents/{a}/versions/1/download").data, b"Alice's salary letter v1\n")
        self.assertEqual(alice.post(f"/api/documents/{a}/versions/9/download").status_code, 404)

    def test_trash_and_restore(self):
        alice, a = self.login("alice"), self.doc_a
        alice.delete(f"/api/documents/{a}")
        self.assertEqual([d["id"] for d in alice.get("/api/trash").get_json()["items"]], [a])
        self.assertEqual(alice.get("/api/documents").get_json()["items"], [])
        self.assertEqual(alice.post(f"/api/documents/{a}/restore").status_code, 200)
        self.assertEqual(alice.post(f"/api/documents/{a}/restore").status_code, 404, "not in trash any more")

    def test_restore_window_is_enforced(self):
        alice, a = self.login("alice"), self.doc_a
        alice.delete(f"/api/documents/{a}")
        self.db.set_context(system=True)
        self.db.run("UPDATE documents SET deleted_at = now() - interval '40 days' WHERE id = %s", (a,))
        self.db.commit()
        self.assertEqual(alice.post(f"/api/documents/{a}/restore").status_code, 400)

    def test_purge_removes_expired_trash_and_its_bytes(self):
        from app.purge import purge

        alice, a = self.login("alice"), self.doc_a
        alice.delete(f"/api/documents/{a}")
        self.db.set_context(system=True)
        self.db.run("UPDATE documents SET deleted_at = now() - interval '40 days' WHERE id = %s", (a,))
        self.db.commit()
        self.assertEqual(purge(self.app), 1)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM documents WHERE id = %s", (a,))[0]["n"], 0)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM blobs")[0]["n"], 1)  # only Bob's remains
        self.assertTrue(self.audit_rows("document_purged"))


@require_db
class ShareLinkRace(IntegrationTest):
    def test_two_requests_cannot_both_use_the_last_download(self):
        """Request B uses the last allowed download while request A is between
        reading the link and counting its download. A must be refused."""
        from unittest import mock

        from app.db import Database
        from app.services import documents as documents_service

        alice = self.login("alice")
        token = alice.post(f"/api/documents/{self.doc_a}/shares",
                           json={"expires_hours": 1, "max_downloads": 1}).get_json()["token"]
        real_read = documents_service.read_version_bytes

        def read_then_race(db, doc, version):
            result = real_read(db, doc, version)
            other = Database(self.db.url)
            other.set_context(system=True)
            other.run("UPDATE share_links SET download_count = download_count + 1")
            other.commit()
            other.close()
            return result

        with mock.patch("app.services.shares.read_version_bytes", read_then_race):
            r = self.anon().post("/api/share/download", json={"token": token})
        self.assertEqual(r.status_code, 404)
        self.assertTrue([e for e in self.audit_rows("share_access_denied")
                         if e["details"].get("reason") == "concurrent_use_of_last_download"])


@require_db
class AiSuggestions(IntegrationTest):
    def _history(self):
        """Give Alice a sharing pattern: two HR documents shared with Bob."""
        alice = self.login("alice")
        for n in range(2):
            doc = alice.upload("/api/documents", f"hr{n}.txt", b"hr", name=f"HR doc {n}", category="HR").get_json()
            alice.post(f"/api/documents/{doc['id']}/grants", json={"email": "bob@test.example", "permission": "read"})
        new = alice.upload("/api/documents", "new.txt", b"new", name="New HR doc", category="HR").get_json()
        return alice, new["id"]

    def test_suggestions_never_grant_anything_by_themselves(self):
        alice, doc = self._history()
        picks = alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"]
        self.assertEqual(picks[0]["email"], "bob@test.example", "most-shared-with, same category, ranks first")
        self.assertLessEqual(len(picks), 3)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM grants WHERE document_id = %s", (doc,))[0]["n"], 0)
        bob = self.login("bob")
        self.assertEqual(bob.post(f"/api/documents/{doc}/download").status_code, 404)

    def test_accepting_creates_the_grant_and_both_steps_are_audited(self):
        alice, doc = self._history()
        pick = alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"][0]
        r = alice.post(f"/api/documents/{doc}/suggestions/{pick['id']}/accept", json={"permission": "read"})
        self.assertEqual(r.status_code, 201)
        grant = self.sql("SELECT permission, granted_via FROM grants WHERE document_id = %s", (doc,))[0]
        self.assertEqual((grant["permission"], grant["granted_via"]), ("read", "ai_suggestion"))
        for action in ("ai_suggestions_generated", "ai_suggestion_accepted", "grant_created"):
            self.assertTrue(self.audit_rows(action, "alice"), action)
        self.assertEqual(self.login("bob").post(f"/api/documents/{doc}/download").status_code, 200)

    def test_rejected_suggestion_cannot_be_accepted_later(self):
        alice, doc = self._history()
        pick = alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"][0]
        alice.post(f"/api/documents/{doc}/suggestions/{pick['id']}/reject")
        self.assertEqual(alice.post(f"/api/documents/{doc}/suggestions/{pick['id']}/accept", json={}).status_code, 404)
        self.assertTrue(self.audit_rows("ai_suggestion_rejected"))

    def test_a_suggestion_cannot_be_accepted_through_another_document(self):
        alice, doc = self._history()
        pick = alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"][0]
        r = alice.post(f"/api/documents/{self.doc_a}/suggestions/{pick['id']}/accept", json={})
        self.assertEqual(r.status_code, 404)

    def test_nobody_else_can_act_on_suggestions(self):
        alice, doc = self._history()
        pick = alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"][0]
        for name in ("bob", "eve", "admin"):
            c = self.login(name)
            self.assertEqual(c.post(f"/api/documents/{doc}/suggestions/{pick['id']}/accept", json={}).status_code,
                             404, name)


@require_db
class AdminViews(IntegrationTest):
    def test_transfer_of_ownership_for_a_leaver(self):
        admin, alice, a = self.login("admin"), self.login("alice"), self.doc_a
        alice.post(f"/api/documents/{a}/shares", json={"expires_hours": 5})
        r = admin.post(f"/api/admin/documents/{a}/transfer", json={"new_owner_email": "bob@test.example"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(alice.post(f"/api/documents/{a}/download").status_code, 404)
        self.assertEqual(self.login("bob").post(f"/api/documents/{a}/download").status_code, 200)
        self.assertEqual(self.login("victor").post(f"/api/documents/{a}/download").status_code, 200, "grants kept")
        self.assertIsNotNone(self.sql("SELECT revoked_at FROM share_links WHERE document_id = %s", (a,))[0]["revoked_at"])
        self.assertTrue(self.audit_rows("ownership_transferred", "admin"))

    def test_transfer_only_to_an_active_owner(self):
        admin = self.login("admin")
        for email in ("victor@test.example", "admin@test.example", "ghost@test.example"):
            r = admin.post(f"/api/admin/documents/{self.doc_a}/transfer", json={"new_owner_email": email})
            self.assertEqual(r.status_code, 400, email)
        self.assertEqual(self.login("alice").post(f"/api/admin/documents/{self.doc_a}/transfer",
                                                  json={"new_owner_email": "bob@test.example"}).status_code, 403)

    def test_probing_raises_an_alert(self):
        eve = self.login("eve")
        for _ in range(6):
            eve.post(f"/api/documents/{self.doc_a}/download")
        alerts = self.login("admin").get("/api/admin/alerts").get_json()["alerts"]
        self.assertIn("probing", [a["kind"] for a in alerts])

    def test_admin_can_see_who_can_reach_a_document(self):
        info = self.login("admin").get(f"/api/admin/documents/{self.doc_a}/access").get_json()
        self.assertEqual(sorted(g["email"] for g in info["grants"]), ["edna@test.example", "victor@test.example"])

    def test_admin_pages_render(self):
        admin = self.login("admin").http
        for path in ("/admin", "/admin/users", "/admin/documents", f"/admin/documents/{self.doc_a}", "/admin/audit",
                     "/admin/audit?outcome=denied&permission_only=1"):
            self.assertEqual(admin.get(path).status_code, 200, path)

    def test_user_pages_render_and_hide_nothing_they_should_not(self):
        alice = self.login("alice").http
        for path in ("/", f"/documents/{self.doc_a}", "/upload", "/trash", "/account", "/share"):
            self.assertEqual(alice.get(path).status_code, 200, path)
        eve = self.login("eve").http
        self.assertEqual(eve.get(f"/documents/{self.doc_a}").status_code, 404)
        self.assertEqual(eve.get("/admin").status_code, 403)
        self.assertEqual(eve.get("/upload").status_code, 403)
