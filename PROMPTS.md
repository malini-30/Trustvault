# PROMPTS.md

How AI was used to build TrustVault, and where it was wrong.

> **Keep writing this as you go.** The brief marks this file on evidence that it
> grew during the week (commit history), with at least five dated entries, two of
> them about authorization or the audit trail. The entries below are real: they
> are the mistakes made and caught during the first build session. Replace each
> `COMMIT-LINK` with the link to the commit where the fix landed once the
> repository is pushed, and add a new entry every time the tool gets something wrong.

Tool: Claude (Anthropic), used in a chat-plus-code workspace. Reused context:
[`ai-context/SECURITY_RULES.md`](ai-context/SECURITY_RULES.md), pasted at the start
of every session, and the review checklist at the end of this file.

---

## 2026-10-24 · Entry 1 · Shared trigger crashed share-link creation (access control)

**Asked:** "Write one trigger function that copies `owner_id` from `documents` onto
`grants`, `share_links` and `ai_suggestions` on insert, so their RLS policies never
need to reference `documents`; also refuse grants to inactive users."

**Got:** a single `tv_fill_owner()` with
`IF TG_TABLE_NAME = 'grants' AND (... NEW.user_id ...) AND NOT EXISTS (...)`.

**Wrong:** it reads as if the `user_id` check only runs for `grants`, but plpgsql
resolves `NEW.user_id` when the expression runs, whatever the left side of `AND`
says. On `share_links` (no such column) every insert failed with
`record "new" has no field "user_id"`, so every share-link creation returned 500.
It looked like a logic shortcut and was not. Found by the isolation tests on the
first run (`KeyError: 'token'` in all three modes).

**Did instead:** nested `IF TG_TABLE_NAME = 'grants' THEN IF ... END IF; END IF;`
with a comment explaining why. Re-ran all three isolation modes.
**Commit:** COMMIT-LINK

## 2026-10-24 · Entry 2 · The two locks disagreed about trashed documents (access control)

**Asked:** "Write the `document_versions` SELECT policy: the owner, a grantee, or a
holder of a live share token may read versions; never admins."

**Got:** `d.owner_id = tv_uid() OR (d.deleted_at IS NULL AND (grant OR share))`.

**Wrong:** the owner clause sat outside the `deleted_at IS NULL` check, so the
database let an owner read the content of a document in the trash, while the
application's `decide()` refuses it. Two locks that disagree mean one of them is
not really a lock. I only noticed because I ran the isolation suite in a mode
where the application's decision is removed (`rls_only`): "owner downloads a
trashed document" passed there and failed in the others.

**Did instead:** moved `deleted_at IS NULL` to the top of the policy so trashed
content is unreachable for everyone until restore, and added
`test_content_of_a_trashed_document_is_hidden_even_from_its_owner`.
**Commit:** COMMIT-LINK

## 2026-10-24 · Entry 3 · "Deleted" when nothing was deleted (access control, fail-open)

**Asked:** "Soft delete: set `deleted_at` and revoke the document's share links."

**Got:** a plain `UPDATE documents SET deleted_at = now() ...` followed by success.

**Wrong:** when row-level security refuses an UPDATE it does not raise; it matches
zero rows. With the application check removed, a reader's delete request matched
nothing and the API still answered 200 "deleted". Not a leak, but a fail-open
pattern: the code reported an action the database had refused. Same issue in
`restore`, which also assumed the document was in the trash and crashed with
`TypeError` when it was not.

**Did instead:** every write that should affect exactly one row checks its row
count and raises 404 otherwise; `restore` checks `deleted_at` before using it.
**Commit:** COMMIT-LINK

## 2026-10-24 · Entry 4 · A refused attempt that never reached the audit trail (audit)

**Asked:** "Record refused attempts with the raw id the attacker sent, so probing is visible."

**Got:** `details={"raw_id": str(document_id)[:80]}` written to a `jsonb` column.

**Wrong:** the raw id is attacker-controlled. Requesting `/api/documents/%00`
put a NUL byte into the details; PostgreSQL `jsonb` rejects `\u0000`; the audit
insert failed; the request became a 500 **and the refusal was lost**. Exactly the
attempt an investigator most wants to see was the one the system failed to record.
Found by `test_malformed_ids_are_404_not_500`.

**Did instead:** `audit._clean()` replaces control characters in every string that
goes into an audit row (details, user agent, IP), and e-mail validation now rejects
control characters before they reach a query.
**Commit:** COMMIT-LINK

## 2026-10-24 · Entry 5 · The tests passed with four checks deleted (authorization, audit)

**Asked:** "Write tests proving each user can only reach their own documents,
covering sessions, share links and the guard triggers."

**Got:** about 140 tests, all green, with good-looking coverage.

**Wrong:** green tests prove nothing about whether they would notice a missing
check. I wrote `scripts/mutation_check.py`, which deletes one check at a time and
reruns the suite (the exact thing the judges will do). First run: **25/29 caught**.
Survivors:
1. The trigger branch stopping editors from deleting: redundant, because
   PostgreSQL also refuses an UPDATE that would make the row invisible to the
   editor. No test isolated the trigger.
2. The session loader's `is_active` check: every test deactivated users through
   the service, which also deletes sessions, so the check never ran alone.
3. The share-link counter's compare-and-set: no test raced two downloads.
4. The token-holder branch of the share-link trigger: the test changed
   `expires_at`, which a different branch already caught.

**Did instead:** a test per survivor (`test_guard_trigger_blocks_what_policies_cannot_express`,
`test_session_check_rejects_inactive_users_on_its_own`,
`test_two_requests_cannot_both_use_the_last_download`, plus a counter-reset case).
Now 29/29, and the script runs in CI.
**Commit:** COMMIT-LINK

## 2026-10-24 · Entry 6 · A test that was testing the test client

**Asked:** "Test that a file name with quotes and CRLF cannot inject response headers."

**Got:** a test uploading `evil";\r\nSet-Cookie: x=1.txt` through the HTTP test client.

**Wrong:** the multipart encoder truncated the name at the quote before it reached
the app, so the upload failed validation ("needs an extension") and the header code
under test never ran. A passing version of that test would have been meaningless.

**Did instead:** call `file_response()` directly with the hostile name and assert
on the produced header.
**Commit:** COMMIT-LINK

## 2026-10-24 · Entry 7 · Design gap found while writing THREATS.md (authorization)

**Asked:** "Admins must never read documents. Check the design for any way around that."

**Got:** confirmation that `decide()` gives admins nothing and the version and blob
policies have no admin clause.

**Wrong:** true but incomplete. An admin can create an owner-role account they
control and transfer a document to it, or reset a user's password and sign in as
them. The AI checked the direct path and stopped.

**Did instead:** documented it as accepted risk T22 (both paths are audited,
hash-chained and the transfer raises an alert); two-person approval is the next
feature. **Commit:** COMMIT-LINK

---

## Template for new entries

```
## YYYY-MM-DD · Entry N · <short title> (<area>)
**Asked:** <the prompt, or a fair summary>
**Got:** <what the tool produced>
**Wrong:** <specifically what was wrong, and how you noticed>
**Did instead:** <the fix> **Commit:** <link>
```

## Review checklist I apply to every AI-written change

1. Does every new route that takes a document id call `authorize()` first? (`test_route_coverage.py` enforces it.)
2. Does any new query read `documents`, `document_versions`, `grants`, `share_links` or `blobs` in the system context? Why?
3. Does every write that should hit one row check its row count?
4. Is the audit row in the same transaction as the action, and is a refusal queued with `audit.deny()`?
5. Could anything attacker-controlled reach SQL text, a header, a log line or a CSV cell unescaped?
6. Run `scripts/mutation_check.py`. A new check needs a new mutation, and it must be caught.
