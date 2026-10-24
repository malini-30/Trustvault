"""One user cannot reach another user's documents.

The same suite runs three times:
  * IsolationBothLocks  - the system as deployed;
  * IsolationAppOnly    - row-level security switched off: the application's
                          authorize() must hold on its own;
  * IsolationRlsOnly    - authorize()'s decision removed: the database must hold
                          on its own.
So removing either lock makes a test fail, and removing both makes many fail.
"""
from datetime import datetime, timedelta, timezone

from .base import IntegrationTest, require_db

TXT = b"replacement contents\n"


class IsolationSuite:
    # ------------------------------------------------ the outsider (eve)
    def test_outsider_is_refused_on_every_document_route(self):
        eve, a = self.login("eve"), self.doc_a
        some_user = self.users["victor"]["id"]
        attempts = [
            ("GET", f"/api/documents/{a}", None),
            ("PATCH", f"/api/documents/{a}", {"name": "pwned"}),
            ("DELETE", f"/api/documents/{a}", None),
            ("POST", f"/api/documents/{a}/restore", None),
            ("POST", f"/api/documents/{a}/download", None),
            ("GET", f"/api/documents/{a}/versions", None),
            ("POST", f"/api/documents/{a}/versions/1/download", None),
            ("GET", f"/api/documents/{a}/grants", None),
            ("POST", f"/api/documents/{a}/grants", {"email": "eve@test.example", "permission": "edit"}),
            ("DELETE", f"/api/documents/{a}/grants/{some_user}", None),
            ("GET", f"/api/documents/{a}/shares", None),
            ("POST", f"/api/documents/{a}/shares", {"expires_hours": 24}),
            ("POST", f"/api/documents/{a}/suggestions", None),
            ("GET", f"/api/documents/{a}/suggestions", None),
        ]
        for method, url, body in attempts:
            kw = {"json": body} if body is not None else {}
            resp = getattr(eve, method.lower())(url, **kw)
            self.assertEqual(resp.status_code, 404, f"{method} {url} -> {resp.status_code}")
        resp = eve.upload(f"/api/documents/{a}/versions", "x.txt", TXT)
        self.assertEqual(resp.status_code, 404, "upload new version")
        # Nothing changed.
        row = self.sql("SELECT name, current_version, deleted_at FROM documents WHERE id = %s", (a,))[0]
        self.assertEqual((row["name"], row["current_version"], row["deleted_at"]), ("Salary letter", 1, None))
        self.assertEqual(len(self.sql("SELECT 1 FROM grants WHERE document_id = %s", (a,))), 2)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM share_links")[0]["n"], 0)

    def test_outsider_finds_nothing_in_search(self):
        eve = self.login("eve")
        for query in ("", "?q=Salary", "?owner=alice", "?category=HR", "?scope=shared", "?q=%25", "?q=_"):
            items = eve.get("/api/documents" + query).get_json()["items"]
            self.assertEqual(items, [], query)

    def test_one_owner_cannot_reach_another_owners_document(self):
        alice = self.login("alice")
        self.assertDenied(alice.get(f"/api/documents/{self.doc_b}"))
        self.assertDenied(alice.post(f"/api/documents/{self.doc_b}/download"))
        names = [d["name"] for d in alice.get("/api/documents").get_json()["items"]]
        self.assertNotIn("Bob contract", names)

    # ---------------------------------------------------- reader (victor)
    def test_reader_can_read_but_not_change_delete_or_share(self):
        victor, a = self.login("victor"), self.doc_a
        self.assertEqual(victor.get(f"/api/documents/{a}").status_code, 200)
        r = victor.post(f"/api/documents/{a}/download")
        self.assertEqual((r.status_code, r.data), (200, b"Alice's salary letter v1\n"))
        self.assertDenied(victor.patch(f"/api/documents/{a}", json={"name": "renamed"}), "rename")
        self.assertDenied(victor.upload(f"/api/documents/{a}/versions", "v2.txt", TXT), "new version")
        self.assertDenied(victor.delete(f"/api/documents/{a}"), "delete")
        self.assertDenied(victor.post(f"/api/documents/{a}/grants", json={"email": "eve@test.example",
                                                                         "permission": "read"}), "grant onward")
        self.assertDenied(victor.get(f"/api/documents/{a}/grants"), "list grants", "grants", self.users["victor"]["id"])
        self.assertDenied(victor.post(f"/api/documents/{a}/shares", json={"expires_hours": 2}), "share link")
        self.assertDenied(victor.get(f"/api/documents/{a}/shares"), "list links", "shares")
        row = self.sql("SELECT name, current_version, deleted_at FROM documents WHERE id = %s", (a,))[0]
        self.assertEqual((row["name"], row["current_version"], row["deleted_at"]), ("Salary letter", 1, None))
        self.assertFalse(self.sql("SELECT 1 FROM grants WHERE user_id = %s", (self.users["eve"]["id"],)))

    # ------------------------------------------------------ editor (edna)
    def test_editor_can_edit_but_not_delete_share_or_regrant(self):
        edna, a = self.login("edna"), self.doc_a
        self.assertEqual(edna.patch(f"/api/documents/{a}", json={"name": "Edited by Edna"}).status_code, 200)
        self.assertEqual(edna.upload(f"/api/documents/{a}/versions", "v2.txt", TXT).status_code, 201)
        self.assertDenied(edna.delete(f"/api/documents/{a}"), "delete")
        self.assertDenied(edna.post(f"/api/documents/{a}/grants", json={"email": "eve@test.example",
                                                                       "permission": "edit"}), "grant onward")
        self.assertDenied(edna.delete(f"/api/documents/{a}/grants/{self.users['victor']['id']}"), "revoke other")
        self.assertDenied(edna.post(f"/api/documents/{a}/shares", json={"expires_hours": 2}), "share link")
        self.assertDenied(edna.post(f"/api/documents/{a}/suggestions"), "AI suggestions", "suggestions")
        self.assertIsNone(self.sql("SELECT deleted_at FROM documents WHERE id = %s", (a,))[0]["deleted_at"])
        self.assertEqual(self.sql("SELECT count(*) AS n FROM grants WHERE document_id = %s", (a,))[0]["n"], 2)

    # ------------------------------------------------------------- admin
    def test_admin_cannot_read_document_contents(self):
        admin, a = self.login("admin"), self.doc_a
        self.assertDenied(admin.post(f"/api/documents/{a}/download"), "download")
        self.assertDenied(admin.post(f"/api/documents/{a}/versions/1/download"), "version download")
        self.assertDenied(admin.post(f"/api/documents/{a}/grants", json={"email": "admin@test.example",
                                                                        "permission": "read"}), "self-grant")
        # Metadata is visible to admins by design, through the admin views.
        names = [d["name"] for d in admin.get("/api/admin/documents").get_json()["documents"]]
        self.assertIn("Salary letter", names)

    # -------------------------------------------------------- revocation
    def test_revoking_a_grant_takes_effect_on_the_next_request(self):
        victor, alice, a = self.login("victor"), self.login("alice"), self.doc_a
        self.assertEqual(victor.post(f"/api/documents/{a}/download").status_code, 200)
        self.assertEqual(alice.delete(f"/api/documents/{a}/grants/{self.users['victor']['id']}").status_code, 200)
        # Same browser, same session, no re-login: refused immediately.
        self.assertDenied(victor.post(f"/api/documents/{a}/download"), "download after revoke")
        self.assertDenied(victor.post(f"/api/documents/{a}/versions/1/download"), "old version after revoke")
        self.assertDenied(victor.get(f"/api/documents/{a}"), "metadata after revoke")
        self.assertEqual(victor.get("/api/documents").get_json()["items"], [])

    def test_downgrading_edit_to_read_stops_edits_immediately(self):
        edna, alice, a = self.login("edna"), self.login("alice"), self.doc_a
        self.assertEqual(alice.post(f"/api/documents/{a}/grants", json={"email": "edna@test.example",
                                                                       "permission": "read"}).status_code, 201)
        self.assertDenied(edna.patch(f"/api/documents/{a}", json={"name": "still editing?"}), "edit after downgrade")
        self.assertEqual(edna.post(f"/api/documents/{a}/download").status_code, 200)

    def test_deleted_document_is_unreachable_except_for_owner_restore(self):
        victor, alice, a = self.login("victor"), self.login("alice"), self.doc_a
        self.assertEqual(alice.delete(f"/api/documents/{a}").status_code, 200)
        self.assertDenied(victor.post(f"/api/documents/{a}/download"), "grantee after delete")
        self.assertDenied(victor.get(f"/api/documents/{a}"), "grantee metadata after delete")
        self.assertDenied(victor.post(f"/api/documents/{a}/restore"), "grantee restore")
        self.assertDenied(alice.post(f"/api/documents/{a}/download"), "owner download while in trash")
        self.assertEqual(alice.post(f"/api/documents/{a}/restore").status_code, 200)
        self.assertEqual(victor.post(f"/api/documents/{a}/download").status_code, 200)

    # ------------------------------------------------------- share links
    def test_share_link_respects_limit_revocation_expiry_and_deletion(self):
        alice, a = self.login("alice"), self.doc_a
        link = alice.post(f"/api/documents/{a}/shares", json={"expires_hours": 2, "max_downloads": 2}).get_json()
        token, anon = link["token"], self.anon()
        self.assertTrue(link["path"].startswith("/share#"))
        for _ in range(2):
            r = anon.post("/api/share/download", json={"token": token})
            self.assertEqual((r.status_code, r.data), (200, b"Alice's salary letter v1\n"))
        self.assertDenied(anon.post("/api/share/download", json={"token": token}), "over the limit")

        link2 = alice.post(f"/api/documents/{a}/shares", json={"expires_hours": 2}).get_json()
        self.assertEqual(anon.post("/api/share/info", json={"token": link2["token"]}).status_code, 200)
        self.assertEqual(alice.delete(f"/api/documents/{a}/shares/{link2['id']}").status_code, 200)
        self.assertDenied(anon.post("/api/share/download", json={"token": link2["token"]}), "after revoke")

        link3 = alice.post(f"/api/documents/{a}/shares", json={"expires_hours": 2}).get_json()
        d = self.db
        d.set_context(system=True)
        d.run("UPDATE share_links SET expires_at = %s WHERE id = %s",
              (datetime.now(timezone.utc) - timedelta(seconds=1), link3["id"]))
        d.commit()
        self.assertDenied(anon.post("/api/share/download", json={"token": link3["token"]}), "after expiry")

        link4 = alice.post(f"/api/documents/{a}/shares", json={"expires_hours": 2}).get_json()
        alice.delete(f"/api/documents/{a}")
        alice.post(f"/api/documents/{a}/restore")
        self.assertDenied(anon.post("/api/share/download", json={"token": link4["token"]}),
                          "links do not come back after delete + restore")
        self.assertDenied(anon.post("/api/share/download", json={"token": "x" * 43}), "unknown token")


@require_db
class IsolationBothLocks(IsolationSuite, IntegrationTest):
    MODE = "both"


@require_db
class IsolationAppOnly(IsolationSuite, IntegrationTest):
    MODE = "app_only"


@require_db
class IsolationRlsOnly(IsolationSuite, IntegrationTest):
    MODE = "rls_only"
