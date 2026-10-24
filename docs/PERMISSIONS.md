# The permission model

## In one paragraph

Every document has exactly one **owner**. Nobody else can reach it unless the
owner gives a **named person** a **grant** on that one document, either `read`
or `edit`. There are no folders, no groups and no inheritance, so access to one
file never implies access to another. Owners can also create **share links** for
people without an account; a link opens one document, expires, can be capped
and revoked. The **admin** role manages people and investigates activity; it
does **not** read documents. Every decision is made on the server, on every
request, twice: once by the application and once by the database.

## Roles (what an account can be)

| Role | Can | Cannot |
|---|---|---|
| `admin` | Create, deactivate and change roles of users; reset passwords; see every document's metadata and who can reach it; read and export the whole audit trail; verify the audit chain; see alerts; transfer ownership of a leaver's document | Open, download or edit any document (unless an owner grants them, like anyone else); create grants or share links on others' documents; change or delete audit rows; deactivate themselves |
| `owner` | Upload documents; everything on documents they own; whatever their grants allow on others' documents | Reach anything they were not granted |
| `viewer` | Whatever their grants allow | Upload; reach anything they were not granted |

## Relationships (what a person is to one document)

| Action on a document | Owner | `edit` grant | `read` grant | Anyone else (incl. admin) |
|---|---|---|---|---|
| See it in search, view metadata | ✓ | ✓ | ✓ | ✗ (404) |
| Download current or any old version | ✓ | ✓ | ✓ | ✗ |
| Rename, recategorise, upload a new version | ✓ | ✓ | ✗ | ✗ |
| Move to trash, restore | ✓ | ✗ | ✗ | ✗ |
| Grant, change, revoke access | ✓ | ✗ | ✗ | ✗ |
| Create or revoke share links | ✓ | ✗ | ✗ | ✗ |
| Ask for / accept AI suggestions | ✓ | ✗ | ✗ | ✗ |

Extra rules:

- A document in the trash is unreachable by everyone, including the owner's
  download, until the owner restores it. Its share links are revoked
  permanently on deletion and do not come back on restore. Its grants do come
  back on restore (the owner deleted the file, not the decision about who may
  read it).
- Editors cannot share onward. Edit means "change the content", not "decide
  who sees it". This is the most common escalation path in real systems.
- Old versions are judged by the grant held **now**. Revoking access revokes
  every version.
- A deactivated user's grants remain as records but cannot be used: the account
  cannot sign in and all its sessions were deleted.

## Why per-document grants and nothing else

The brief's first failure story is "someone is given access to a folder so they
can see one file, and they can now see forty". Folder inheritance and groups are
exactly the mechanisms that cause it: the person granting access cannot see the
full consequence of the grant. With per-document grants, what you grant is what
they get. The cost is convenience (sharing 40 files is 40 grants), which I chose
to pay. Groups are the first thing I would add, and the design is ready for it:
a `group_grants` table and one more clause in `decide()` and in each policy.

## Where the decision is made

| Lock | Where | What it does |
|---|---|---|
| A: application | `app/authz.py`: `decide()` (pure function) and `authorize()` | Every service function that receives a document id calls `authorize()` first. On refusal: audit row + 404. |
| B: database | `migrations/002_rls.sql` | Row-level security policies, `FORCE`d, read the user id from a transaction-local setting. A row the user may not see is simply not returned; a write they may not make raises an error, which the app turns into audit row + 404. |

The two are written independently and tested independently:
`tests/test_isolation.py` runs the same attacks with only lock A, only lock B,
and both. `scripts/mutation_check.py` removes each check in turn and confirms the
tests fail.

### Download, step by step (the interview question)

1. `POST /api/documents/<id>/download` → `app/web/api.py:download_document`
   (session and CSRF already checked in `app/__init__.py`).
2. → `app/services/documents.py:download()`, whose first line is
   `doc = authorize(db, user, doc_id, Action.READ)`.
3. `authorize()` loads the document and the caller's grant **through RLS**, then
   asks `decide()`. Refused → `audit.deny(...)` and `raise NotFound()`.
4. Allowed → `read_version_bytes()` selects the version row (RLS on
   `document_versions` again: no admin clause, no trashed documents), then the
   encrypted blob (RLS on `blobs`, chained to the version), then decrypts it with
   a key bound to this document id and version.
5. `audit.record("download", ...)` with version and SHA-256, in the same
   transaction. The response is sent only after that commit succeeds.

**If line 2's `authorize()` call were removed**, nothing is disclosed, but the
system degrades: for an outsider the document query returns no row through RLS,
so there is nothing to decrypt and the request fails (as an error rather than a
clean 404). An admin, who can see metadata rows, gets 404 at step 4 because the
version policy excludes admins. What is lost is the audited refusal, the clean
404, and every rule only the application expresses. The tests notice in three
places: `test_route_coverage.py` expects an `access_denied` audit row for every
document route, the app-only run of `test_isolation.py` loses its only lock, and
`scripts/mutation_check.py` performs exactly this deletion as mutation 10.
