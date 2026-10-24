"""Sessions, revocation of people, CSRF, request hygiene and response headers."""
from .base import PASSWORD, IntegrationTest, require_db


@require_db
class Sessions(IntegrationTest):
    def test_deactivating_a_user_ends_their_session_immediately(self):
        victor, admin = self.login("victor"), self.login("admin")
        self.assertEqual(victor.post(f"/api/documents/{self.doc_a}/download").status_code, 200)
        r = admin.patch(f"/api/admin/users/{self.users['victor']['id']}", json={"is_active": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(victor.post(f"/api/documents/{self.doc_a}/download").status_code, 401)
        self.assertEqual(victor.get("/api/me").status_code, 401)
        login = self.app.test_client().post("/api/auth/login", json={"email": "victor@test.example", "password": PASSWORD})
        self.assertEqual(login.status_code, 401)

    def test_session_check_rejects_inactive_users_on_its_own(self):
        # Even if a deactivation bypassed the service (a direct SQL fix, a future
        # bulk tool) and left session rows behind, the session is refused.
        victor = self.login("victor")
        self.db.set_context(system=True)
        self.db.run("UPDATE users SET is_active = false WHERE email = 'victor@test.example'")
        self.db.commit()
        self.assertEqual(self.sql("SELECT count(*) AS n FROM sessions")[0]["n"], 1, "session row still exists")
        self.assertEqual(victor.get("/api/me").status_code, 401)

    def test_changing_a_role_ends_sessions(self):
        alice, admin = self.login("alice"), self.login("admin")
        admin.patch(f"/api/admin/users/{self.users['alice']['id']}", json={"role": "viewer"})
        self.assertEqual(alice.get("/api/me").status_code, 401)

    def test_password_change_signs_out_other_sessions_only(self):
        laptop, phone = self.login("alice"), self.login("alice")
        r = laptop.post("/api/me/password", json={"current_password": PASSWORD, "new_password": "A-new-passphrase-1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(laptop.get("/api/me").status_code, 200)
        self.assertEqual(phone.get("/api/me").status_code, 401)

    def test_admin_password_reset_ends_sessions(self):
        victor, admin = self.login("victor"), self.login("admin")
        admin.post(f"/api/admin/users/{self.users['victor']['id']}/reset-password", json={"password": "Reset-by-admin-1"})
        self.assertEqual(victor.get("/api/me").status_code, 401)

    def test_logout_kills_the_token_server_side(self):
        alice = self.login("alice")
        cookie = alice.http.get_cookie("tv_session").value
        alice.post("/api/auth/logout")
        thief = self.app.test_client()
        thief.set_cookie("tv_session", cookie)
        self.assertEqual(thief.get("/api/me").status_code, 401)

    def test_idle_session_expires(self):
        alice = self.login("alice")
        self.db.set_context(system=True)
        self.db.run("UPDATE sessions SET last_seen_at = now() - interval '2 hours'")
        self.db.commit()
        self.assertEqual(alice.get("/api/me").status_code, 401)

    def test_every_login_gets_a_new_token(self):
        a, b = self.login("alice"), self.login("alice")
        self.assertNotEqual(a.http.get_cookie("tv_session").value, b.http.get_cookie("tv_session").value)

    def test_session_tokens_are_stored_hashed(self):
        alice = self.login("alice")
        raw = alice.http.get_cookie("tv_session").value
        stored = [r["token_hash"] for r in self.sql("SELECT token_hash FROM sessions")]
        self.assertNotIn(raw, stored)

    def test_lockout_after_repeated_failures(self):
        c = self.app.test_client()
        for _ in range(5):
            c.post("/api/auth/login", json={"email": "bob@test.example", "password": "wrong-wrong"})
        r = c.post("/api/auth/login", json={"email": "bob@test.example", "password": PASSWORD})
        self.assertEqual(r.status_code, 401, "correct password refused while locked")
        self.assertIsNotNone(self.sql("SELECT locked_until FROM users WHERE email = 'bob@test.example'")[0]["locked_until"])

    def test_unknown_and_wrong_password_look_the_same(self):
        c = self.app.test_client()
        a = c.post("/api/auth/login", json={"email": "nobody@test.example", "password": "x" * 12})
        b = c.post("/api/auth/login", json={"email": "alice@test.example", "password": "x" * 12})
        self.assertEqual((a.status_code, a.get_json()["message"]), (b.status_code, b.get_json()["message"]))

    def test_login_rate_limit(self):
        c = self.app.test_client()
        codes = [c.post("/api/auth/login", json={"email": "x@test.example", "password": "y" * 12}).status_code
                 for _ in range(12)]
        self.assertIn(429, codes)

    def test_admin_cannot_lock_themselves_out(self):
        admin = self.login("admin")
        r = admin.patch(f"/api/admin/users/{self.users['admin']['id']}", json={"is_active": False})
        self.assertEqual(r.status_code, 400)

    def test_admin_only_endpoints_refuse_everyone_else(self):
        for name in ("alice", "victor", "eve"):
            c = self.login(name)
            for path in ("/api/admin/audit/verify", "/api/admin/audit/head", "/api/admin/alerts",
                         "/api/admin/documents", "/api/admin/audit/export.csv", "/api/admin/users"):
                self.assertEqual(c.get(path).status_code, 403, f"{name} {path}")

    def test_admin_services_check_the_role_themselves(self):
        """Defence in depth: the service layer refuses even if a route forgot its decorator."""
        from werkzeug.exceptions import Forbidden

        from app.services import admin as admin_service
        from app.services import users as users_service

        with self.app.test_request_context("/"):
            from app import get_db

            db, alice = get_db(), self.users["alice"]
            for call in (lambda: users_service.list_users(db, alice),
                         lambda: users_service.update_user(db, alice, self.users["eve"]["id"], role="admin"),
                         lambda: admin_service.documents_overview(db, alice),
                         lambda: admin_service.audit_events(db, alice),
                         lambda: admin_service.transfer_ownership(db, alice, self.doc_b, "alice@test.example")):
                with self.assertRaises(Forbidden):
                    call()

    def test_non_admins_cannot_manage_users(self):
        for name in ("alice", "victor"):
            c = self.login(name)
            self.assertEqual(c.get("/api/admin/users").status_code, 403)
            self.assertEqual(c.patch(f"/api/admin/users/{self.users['eve']['id']}", json={"role": "admin"}).status_code, 403)
            self.assertEqual(c.post("/api/admin/users", json={"email": "new@test.example", "full_name": "N",
                                                              "role": "admin", "password": "x" * 14}).status_code, 403)


@require_db
class RequestHygiene(IntegrationTest):
    def test_state_changes_require_the_csrf_token(self):
        alice = self.login("alice")
        alice.csrf = None
        self.assertEqual(alice.patch(f"/api/documents/{self.doc_a}", json={"name": "csrf"}).status_code, 403)
        self.assertEqual(alice.post(f"/api/documents/{self.doc_a}/download").status_code, 403)
        alice.csrf = "forged-token"
        self.assertEqual(alice.delete(f"/api/documents/{self.doc_a}").status_code, 403)
        self.assertEqual(self.sql("SELECT name FROM documents WHERE id = %s", (self.doc_a,))[0]["name"], "Salary letter")
        self.assertTrue(self.audit_rows("csrf_rejected"))

    def test_cross_site_requests_are_refused(self):
        alice = self.login("alice")
        r = alice.post(f"/api/documents/{self.doc_a}/download", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status_code, 403)

    def test_download_cannot_be_triggered_by_a_plain_link(self):
        alice = self.login("alice")
        self.assertEqual(alice.get(f"/api/documents/{self.doc_a}/download").status_code, 405)

    def test_json_endpoints_refuse_form_encoded_bodies(self):
        alice = self.login("alice")
        r = alice.post(f"/api/documents/{self.doc_a}/grants", data={"email": "eve@test.example", "permission": "edit"})
        self.assertEqual(r.status_code, 400)

    def test_mass_assignment_is_refused(self):
        edna = self.login("edna")
        r = edna.patch(f"/api/documents/{self.doc_a}", json={"name": "ok", "owner_id": self.users["edna"]["id"]})
        self.assertEqual(r.status_code, 400)
        row = self.sql("SELECT owner_id, name FROM documents WHERE id = %s", (self.doc_a,))[0]
        self.assertEqual((row["owner_id"], row["name"]), (self.users["alice"]["id"], "Salary letter"))
        r = edna.patch(f"/api/documents/{self.doc_a}", json={"deleted_at": None})
        self.assertEqual(r.status_code, 400)

    def test_malformed_ids_are_404_not_500(self):
        eve = self.login("eve")
        for bad in ("1", "' OR '1'='1", "../../etc/passwd", "%00", "0" * 400):
            self.assertEqual(eve.get(f"/api/documents/{bad}").status_code, 404, bad)

    def test_unauthenticated_requests_get_401(self):
        anon = self.app.test_client()
        self.assertEqual(anon.get("/api/documents").status_code, 401)
        self.assertEqual(anon.get(f"/api/documents/{self.doc_a}").status_code, 401)
        self.assertEqual(anon.post(f"/api/documents/{self.doc_a}/download").status_code, 401)

    def test_downloads_are_never_rendered_or_cached(self):
        r = self.login("victor").post(f"/api/documents/{self.doc_a}/download")
        self.assertEqual(r.mimetype, "application/octet-stream")
        self.assertTrue(r.headers["Content-Disposition"].startswith("attachment;"))
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_hostile_filename_cannot_inject_headers(self):
        from app.web.common import file_response

        with self.app.test_request_context("/"):
            resp = file_response('evil";\r\nSet-Cookie: x=1.txt', b"data")
        disposition = resp.headers["Content-Disposition"]
        self.assertNotIn("\r", disposition)
        self.assertNotIn("\n", disposition)
        self.assertEqual(disposition.count('"'), 2)
        self.assertNotIn("Set-Cookie", resp.headers)

    def test_errors_do_not_leak_internals(self):
        r = self.login("alice").get(f"/api/documents/{self.doc_a}/versions/abc")
        self.assertIn(r.status_code, (404, 405))
        self.assertNotIn("Traceback", r.get_data(as_text=True))


@require_db
class UploadsThroughTheApi(IntegrationTest):
    def test_viewers_cannot_upload(self):
        r = self.login("victor").upload("/api/documents", "a.txt", b"hello", category="HR")
        self.assertEqual(r.status_code, 403)
        self.assertTrue(self.audit_rows("upload_denied", "victor"))

    def test_disguised_and_active_files_are_rejected(self):
        alice = self.login("alice")
        for name, data in (("cv.pdf", b"MZ\x90\x00\x03"), ("page.txt", b"<html><script>x</script>"),
                           ("logo.svg", b"<svg/>"), ("run.exe", b"MZ")):
            self.assertEqual(alice.upload("/api/documents", name, data, category="HR").status_code, 400, name)
        self.assertEqual(self.sql("SELECT count(*) AS n FROM documents")[0]["n"], 2)

    def test_oversized_upload_is_rejected_before_storage(self):
        self.app.config["TV"].MAX_UPLOAD_MB = 1
        r = self.login("alice").upload("/api/documents", "big.txt", b"a" * (1024 * 1024 + 10), category="HR")
        self.assertIn(r.status_code, (400, 413))
        self.assertEqual(self.sql("SELECT count(*) AS n FROM blobs")[0]["n"], 2)

    def test_stored_bytes_are_encrypted(self):
        blobs = self.sql("SELECT data FROM blobs")
        self.assertTrue(blobs)
        for b in blobs:
            self.assertNotIn(b"salary", b["data"].lower())

    def test_category_is_validated(self):
        r = self.login("alice").upload("/api/documents", "a.txt", b"x", category="Secret'; DROP TABLE x")
        self.assertEqual(r.status_code, 400)


@require_db
class UserServiceEdgeCases(IntegrationTest):
    def test_create_user_validates_input(self):
        admin = self.login("admin")
        bad = [{"email": "nope", "full_name": "x", "role": "viewer", "password": "x" * 14},
               {"email": "a@test.example", "full_name": "x", "role": "root", "password": "x" * 14},
               {"email": "a@test.example", "full_name": "x", "role": "viewer", "password": "short"},
               {"email": "alice@test.example", "full_name": "dup", "role": "viewer", "password": "x" * 14}]
        for body in bad:
            self.assertEqual(admin.post("/api/admin/users", json=body).status_code, 400, body)
        ok = admin.post("/api/admin/users", json={"email": "New@Test.Example", "full_name": "New", "role": "viewer",
                                                  "password": "x" * 14})
        self.assertEqual(ok.status_code, 201)
        self.assertEqual(ok.get_json()["email"], "new@test.example")
