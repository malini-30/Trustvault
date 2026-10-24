"""Routes nobody thought to test.

Instead of listing routes by hand, this walks Flask's URL map. Every route (API
or HTML, any method) that takes a document id is called by a user with no access
to that document. Each must answer 404 AND leave an access_denied row in the
audit trail, which proves authorize() ran before anything else. A route added
next month without an authorization check fails this test automatically.
"""
import uuid

from .base import IntegrationTest, require_db

ADMIN_PREFIXES = ("/api/admin/", "/admin/")


def fill(rule, doc_id):
    values = {}
    for arg in rule.arguments:
        values[arg] = doc_id if arg == "doc_id" else (1 if arg == "version" else str(uuid.uuid4()))
    path = rule.rule
    for arg, value in values.items():
        path = path.replace(f"<{arg}>", str(value)).replace(f"<int:{arg}>", str(value))
    return path


@require_db
class EveryDocumentRouteIsAuthorized(IntegrationTest):
    def doc_rules(self):
        return [r for r in self.app.url_map.iter_rules() if "doc_id" in r.arguments]

    def test_route_discovery_found_the_routes(self):
        self.assertGreaterEqual(len(self.doc_rules()), 30)

    def test_every_route_refuses_and_audits_an_outsider(self):
        eve = self.login("eve")
        checked = 0
        for rule in self.doc_rules():
            if rule.rule.startswith(ADMIN_PREFIXES):
                continue
            path = fill(rule, self.doc_a)
            for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
                before = len(self.audit_rows("access_denied", "eve"))
                if path.startswith("/api/"):
                    kw = {} if method in ("GET", "DELETE") else {"json": {}}
                else:
                    kw = {} if method == "GET" else {"data": {"csrf_token": eve.csrf}}
                resp = getattr(eve, method.lower())(path, **kw)
                self.assertEqual(resp.status_code, 404, f"{method} {rule.rule} answered {resp.status_code}")
                denied = self.audit_rows("access_denied", "eve")
                self.assertEqual(len(denied), before + 1, f"{method} {rule.rule} did not audit the refusal")
                self.assertEqual(denied[-1]["document_id"], self.doc_a)
                checked += 1
        self.assertGreaterEqual(checked, 25)

    def test_admin_document_routes_refuse_non_admins(self):
        for name in ("alice", "eve"):
            c = self.login(name)
            for rule in self.doc_rules():
                if not rule.rule.startswith(ADMIN_PREFIXES):
                    continue
                path = fill(rule, self.doc_a)
                for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
                    kw = {} if method == "GET" else ({"json": {}} if path.startswith("/api/") else
                                                     {"data": {"csrf_token": c.csrf}})
                    resp = getattr(c, method.lower())(path, **kw)
                    self.assertEqual(resp.status_code, 403, f"{name} {method} {rule.rule}")

    def test_nonexistent_document_looks_identical_to_a_forbidden_one(self):
        eve = self.login("eve")
        real = eve.get(f"/api/documents/{self.doc_a}")
        fake = eve.get(f"/api/documents/{uuid.uuid4()}")
        strip = lambda r: {k: v for k, v in r.get_json().items() if k != "request_id"}  # noqa: E731
        self.assertEqual((real.status_code, strip(real)), (fake.status_code, strip(fake)))
