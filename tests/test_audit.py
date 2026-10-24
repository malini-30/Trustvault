"""The audit trail: complete (including refusals) and tamper-evident."""
from app import audit
from app.db import Database, DbError

from .base import TEST_DB, IntegrationTest, require_db


@require_db
class AuditTrail(IntegrationTest):
    def chain(self):
        d = Database(TEST_DB)
        try:
            return audit.verify(d)
        finally:
            d.close()

    def test_every_kind_of_event_is_recorded(self):
        alice, victor, a = self.login("alice"), self.login("victor"), self.doc_a
        victor.post(f"/api/documents/{a}/download")
        alice.patch(f"/api/documents/{a}", json={"category": "Legal"})
        alice.delete(f"/api/documents/{a}/grants/{self.users['victor']['id']}")
        alice.post(f"/api/documents/{a}/shares", json={"expires_hours": 1})
        alice.delete(f"/api/documents/{a}")
        actions = {r["action"] for r in self.audit_rows()}
        for needed in ("upload", "grant_created", "login_success", "download", "document_updated", "grant_revoked",
                       "share_link_created", "document_deleted"):
            self.assertIn(needed, actions)
        dl = self.audit_rows("download", "victor")[0]
        self.assertEqual(dl["document_id"], a)
        self.assertEqual(dl["details"]["version"], 1)
        self.assertEqual(len(dl["details"]["sha256"]), 64)  # proves which exact bytes were read

    def test_refused_attempts_are_recorded_with_who_and_what(self):
        eve = self.login("eve")
        self.assertEqual(eve.post(f"/api/documents/{self.doc_a}/download").status_code, 404)
        self.assertEqual(eve.get("/api/documents/not-a-uuid").status_code, 404)
        denied = self.audit_rows("access_denied", "eve")
        self.assertEqual(len(denied), 2)
        self.assertEqual(denied[0]["document_id"], self.doc_a)
        self.assertEqual(denied[0]["outcome"], "denied")
        self.assertEqual(denied[0]["details"]["attempted"], "read")
        self.assertEqual(denied[1]["details"]["raw_id"], "not-a-uuid")
        self.assertTrue(self.chain()["ok"])

    def test_failed_logins_are_recorded(self):
        r = self.app.test_client().post("/api/auth/login", json={"email": "alice@test.example", "password": "wrong"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(len(self.audit_rows("login_failed")), 1)

    def test_rows_cannot_be_changed_deleted_or_truncated(self):
        d = Database(TEST_DB)
        self.addCleanup(d.close)
        for sql in ("UPDATE audit_events SET actor_email = 'nobody' WHERE id = 1",
                    "DELETE FROM audit_events WHERE id = 1",
                    "TRUNCATE audit_events"):
            with self.assertRaises(DbError, msg=sql):
                d.run(sql)
            d.rollback()
        self.assertTrue(self.chain()["ok"])

    def _bypass_triggers_and(self, sql):
        """Simulate an attacker with table-owner rights who disables the triggers."""
        d = Database(TEST_DB)
        d.run("ALTER TABLE audit_events DISABLE TRIGGER USER")
        d.run(sql)
        d.run("ALTER TABLE audit_events ENABLE TRIGGER USER")
        d.commit()
        d.close()

    def test_editing_a_past_row_is_detected(self):
        self.assertTrue(self.chain()["ok"])
        self._bypass_triggers_and("UPDATE audit_events SET actor_email = 'someone-else@test.example' WHERE id = 2")
        result = self.chain()
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at_id"], 2)

    def test_removing_a_row_is_detected(self):
        self._bypass_triggers_and("DELETE FROM audit_events WHERE id = 3")
        result = self.chain()
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at_id"], 4)

    def test_broken_chain_raises_a_critical_alert(self):
        self._bypass_triggers_and("UPDATE audit_events SET details = '{}'::jsonb WHERE id = 1")
        alerts = self.login("admin").get("/api/admin/alerts").get_json()["alerts"]
        self.assertEqual(alerts[0]["kind"], "audit_chain_broken")

    def test_only_admins_can_read_the_audit_trail(self):
        for name in ("alice", "victor", "eve"):
            self.assertEqual(self.login(name).get("/api/admin/audit").status_code, 403, name)
        self.assertEqual(self.login("admin").get("/api/admin/audit").status_code, 200)

    def test_csv_export_neutralises_formulas(self):
        # The User-Agent header is attacker-controlled and lands in the audit trail.
        r = self.app.test_client().post("/api/auth/login", json={"email": "eve@test.example", "password": "nope"},
                                        headers={"User-Agent": "=cmd|' /C calc'!A0"})
        self.assertEqual(r.status_code, 401)
        body = self.login("admin").get("/api/admin/audit/export.csv").get_data(as_text=True)
        self.assertIn(",'=cmd|", body)
        self.assertNotIn(",=cmd|", body)
