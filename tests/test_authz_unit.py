"""Exhaustive tests of the pure authorization decision. No database needed.

Every combination of (who, grant, deleted?, action) is checked against an
independently written expectation table, so deleting or weakening any branch of
authz.decide() fails here even when row-level security would still have caught
the request in the integration tests."""
import itertools
import unittest
from datetime import datetime, timedelta, timezone

from app.authz import Action, Subject, decide, decide_share

OWNER, OTHER = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"


def expected(relation, grant, deleted, action):
    """The policy, written out as a table rather than code paths."""
    if relation == "inactive":
        return False
    if action is Action.RESTORE:
        return relation == "owner" and deleted
    if deleted:
        return False
    if relation == "owner":
        return True
    if relation == "admin":
        return action is Action.READ and grant in ("read", "edit") or action is Action.EDIT and grant == "edit"
    return {Action.READ: grant in ("read", "edit"), Action.EDIT: grant == "edit"}.get(action, False)


class DecideMatrix(unittest.TestCase):
    def test_every_combination(self):
        relations = ("owner", "stranger", "admin", "inactive")
        for relation, grant, deleted, action in itertools.product(relations, (None, "read", "edit"), (False, True),
                                                                  list(Action)):
            if relation == "owner" and grant:
                continue  # an owner cannot hold a grant on their own document (DB CHECK)
            subject = Subject(id=OWNER if relation == "owner" else OTHER,
                              role={"admin": "admin", "owner": "owner"}.get(relation, "viewer"),
                              is_active=relation != "inactive")
            doc = {"owner_id": OWNER, "deleted_at": datetime.now(timezone.utc) if deleted else None}
            with self.subTest(relation=relation, grant=grant, deleted=deleted, action=action.value):
                self.assertEqual(decide(subject, doc, grant, action), expected(relation, grant, deleted, action))

    def test_admin_role_alone_grants_nothing(self):
        admin = Subject(id=OTHER, role="admin", is_active=True)
        doc = {"owner_id": OWNER, "deleted_at": None}
        for action in Action:
            self.assertFalse(decide(admin, doc, None, action), action)

    def test_missing_subject_or_document_is_refused(self):
        doc = {"owner_id": OWNER, "deleted_at": None}
        owner = Subject(id=OWNER, role="owner", is_active=True)
        for action in Action:
            self.assertFalse(decide(None, doc, "edit", action))
            self.assertFalse(decide(owner, None, "edit", action))

    def test_deactivated_owner_is_refused(self):
        owner = Subject(id=OWNER, role="owner", is_active=False)
        self.assertFalse(decide(owner, {"owner_id": OWNER, "deleted_at": None}, None, Action.READ))

    def test_editor_cannot_manage_or_delete(self):
        editor = Subject(id=OTHER, role="viewer", is_active=True)
        doc = {"owner_id": OWNER, "deleted_at": None}
        self.assertTrue(decide(editor, doc, "edit", Action.EDIT))
        self.assertFalse(decide(editor, doc, "edit", Action.MANAGE))
        self.assertFalse(decide(editor, doc, "edit", Action.DELETE))


class DecideShare(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.doc = {"id": "d1", "deleted_at": None}
        self.link = {"document_id": "d1", "revoked_at": None, "expires_at": self.now + timedelta(hours=1),
                     "max_downloads": 3, "download_count": 0}

    def check(self, **changes):
        link = {**self.link, **{k: v for k, v in changes.items() if k in self.link}}
        doc = {**self.doc, **{k: v for k, v in changes.items() if k in ("deleted_at",)}}
        return decide_share(link, doc, self.now)

    def test_live_link(self):
        self.assertTrue(self.check())

    def test_revoked(self):
        self.assertFalse(self.check(revoked_at=self.now))

    def test_expired_exactly_now(self):
        self.assertFalse(self.check(expires_at=self.now))

    def test_used_up(self):
        self.assertFalse(self.check(download_count=3))
        self.assertTrue(self.check(download_count=2))

    def test_unlimited(self):
        self.assertTrue(self.check(max_downloads=None, download_count=10_000))

    def test_deleted_document(self):
        self.assertFalse(self.check(deleted_at=self.now))

    def test_link_for_another_document(self):
        self.assertFalse(decide_share({**self.link, "document_id": "other"}, self.doc, self.now))

    def test_missing(self):
        self.assertFalse(decide_share(None, self.doc, self.now))
        self.assertFalse(decide_share(self.link, None, self.now))
