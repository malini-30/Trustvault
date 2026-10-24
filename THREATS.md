# THREATS.md

How I believe TrustVault could be broken, what I did about each, how a test
proves it, and what I knowingly left open.

**Status key.** **Closed**: defended, and a test fails if the defence is removed.
**Partial**: reduced, residual risk stated. **Accepted**: known, deliberately left,
with the reason.

**Two locks.** Most document threats below are defended twice: by the application
(`app/authz.py`, lock A) and by PostgreSQL row-level security (`migrations/002_rls.sql`,
lock B). `tests/test_isolation.py` runs the same attacks three times (both locks /
app only / database only), and `scripts/mutation_check.py` deletes 29 individual
checks one at a time and confirms the suite fails for every one (latest run: 29/29).

---

## A. Reaching a document you were not given

**T01. Changing the document id (IDOR).** Any route that takes a document id,
called with someone else's id.
*Defence:* every service function's first line is `authorize()`; RLS returns no
row anyway. Refusal is a 404 identical to "does not exist", and is audited.
*Tests:* `test_isolation.*.test_outsider_is_refused_on_every_document_route` (×3 modes),
`test_rls.test_outsider_sees_no_rows_even_with_unfiltered_queries`. **Closed.**

**T02. A route nobody remembered to protect.** A new endpoint, an HTML page that
duplicates an API call, a version or thumbnail URL.
*Defence:* `test_route_coverage.py` walks Flask's URL map. Every route (API and
HTML, every method) with a document id is called by an outsider and must answer
404 and leave an `access_denied` audit row. A route added later without
`authorize()` fails automatically. **Closed.**

**T03. HTTP method games.** `HEAD`, `OPTIONS`, `GET` on a `POST` route, `PUT`.
*Defence:* Flask routes by method; `HEAD` runs the `GET` view (so the same check);
download is `POST`-only (a `GET` is 405). *Test:* `test_download_cannot_be_triggered_by_a_plain_link`. **Closed.**

**T04. Old versions after access is removed.** "I was revoked, but I kept the URL
of version 1."
*Defence:* version downloads are authorized against the grant held **now**; the
`document_versions` policy is evaluated at query time.
*Test:* `test_revoking_a_grant_takes_effect_on_the_next_request` (old version). **Closed.**

**T05. Documents in the trash.** A grantee (or the owner's download link) reaching
a deleted document.
*Defence:* `decide()` refuses deleted documents for everything except owner restore;
RLS hides trashed rows from non-owners and hides trashed **content** from the owner too.
*Tests:* `test_deleted_document_is_unreachable_except_for_owner_restore`,
`test_content_of_a_trashed_document_is_hidden_even_from_its_owner`. **Closed.**

**T06. Going around the app to the storage.** Guessing blob keys, a public bucket,
a pre-signed URL that keeps working after revocation.
*Defence:* bytes never leave except through the server after authorization; no
pre-signed URLs anywhere; storage keys are random 128-bit values unrelated to ids
or names; blobs are AES-256-GCM encrypted with a per-file key; the `blobs` policy
is chained to the `document_versions` policy.
*Tests:* `test_stored_bytes_are_encrypted`, `test_admin_sees_metadata_but_never_keys_or_bytes`. **Closed.**

**T07. Swapping ciphertext between documents.** Someone with write access to the
blob store copies document A's ciphertext over document B's (so a reader of B
reads A).
*Defence:* the document id and version are GCM associated data; a moved blob fails
to decrypt. *Test:* `test_ciphertext_is_bound_to_its_document_and_version`. **Closed.**

**T08. The administrator reads documents.** Admins see everything else, so the
obvious insider route is "ask an admin" or "steal an admin session".
*Defence:* the admin role grants nothing in `decide()`; the version and blob
policies have no admin clause, so even a bug in the app cannot hand an admin the
content. *Tests:* `test_admin_cannot_read_document_contents` (×3), mutation 16.
**Closed** for direct reading. See T22 for the indirect route.

**T09. Telling "forbidden" from "missing".** A 403 vs 404, different error bodies,
or different timing, confirms that a document id exists.
*Defence:* always 404, same body. *Test:* `test_nonexistent_document_looks_identical_to_a_forbidden_one`.
**Partial:** a real document takes one more query than a random id; the timing
difference is microseconds and I accepted it.

**T10. Search and listings leak metadata.** Names of others' documents through
search, total counts, pagination, owner filters.
*Defence:* the visibility condition is written into the search SQL **and**
enforced by RLS; no total counts are returned (only `has_more`).
*Tests:* `test_outsider_finds_nothing_in_search`, mutation 12. **Closed.**

**T11. LIKE wildcards in search.** `q=%` or `q=_` to enumerate.
*Defence:* wildcards escaped; the search is literal. *Test:* `test_wildcards_in_search_are_literal`. **Closed.**

**T12. SQL injection.** *Defence:* every query is parameterised; no identifier is
ever built from input; ids are validated as UUIDs before use.
*Test:* `test_malformed_ids_are_404_not_500` (injection strings).
**Partial:** RLS does **not** protect against a successful injection, because the
app connects as the table owner and could `ALTER TABLE`. Fix (not done): run
migrations as one role and the app as a second role that owns nothing. Render's
free database gives a single user, which is why I stopped here.

**T13. Crashes as an oracle.** Malformed ids, NUL bytes, huge values producing
500s and stack traces.
*Defence:* ids validated; control characters stripped; generic error pages with a
request id. I found one real case while testing: `%00` in a URL put a NUL into the
audit row, Postgres `jsonb` rejected it, and the refusal became an unlogged 500.
Now sanitised. *Test:* `test_malformed_ids_are_404_not_500`. **Closed.**

## B. Getting more than you were given

**T14. Editors sharing onward.** An `edit` grantee grants a friend or makes a share link.
*Defence:* only the owner manages access (`Action.MANAGE`); the grants and
share-links policies require `owner_id = current user`, and a trigger overwrites
any `owner_id` the caller supplies with the real owner.
*Tests:* `test_editor_can_edit_but_not_delete_share_or_regrant` (×3),
`test_forged_owner_id_on_a_grant_is_overwritten`, mutations 3, 11, 17. **Closed.**

**T15. Readers editing or deleting.** *Tests:* `test_reader_can_read_but_not_change_delete_or_share` (×3),
`test_reader_updates_match_zero_rows`. An UPDATE that RLS matches to zero rows is
treated as a refusal, never reported as success. **Closed.**

**T16. Mass assignment.** `PATCH {"owner_id": me}` or `{"deleted_at": null}`.
*Defence:* explicit allowlist (`name`, `category`), anything else is 400; the
documents guard trigger refuses any owner change outside an admin transfer.
*Tests:* `test_mass_assignment_is_refused`, `test_editor_cannot_delete_or_take_ownership`. **Closed.**

**T17. Granting yourself, a deactivated user, or by the wrong person.**
*Defence:* app checks + DB `CHECK (user_id <> owner_id)` + trigger requiring an
active grantee. *Test:* `test_nobody_but_the_owner_can_grant`. **Closed.**

**T18. Uploading as a viewer / planting a document in someone else's name.**
*Defence:* role check; insert policy requires `owner_id = me AND role = owner`.
*Tests:* `test_viewers_cannot_upload`, `test_owner_cannot_give_a_document_away_or_create_one_for_someone_else`. **Closed.**

**T19. Privilege changes not taking effect.** A demoted or deactivated user keeps
working until their session expires.
*Defence:* any role or status change deletes all that user's sessions; the session
loader also re-checks `is_active` on every request.
*Tests:* `test_changing_a_role_ends_sessions`, `test_session_check_rejects_inactive_users_on_its_own`. **Closed.**

**T20. Admin locking everyone out / promoting themselves.** *Defence:* admins cannot
change their own role or deactivate themselves. Promoting another account is
allowed and audited. **Closed / Accepted.**

**T21. Ownership transfer abuse.** Transfer is the one action that moves access
without the owner. *Defence:* admin only, target must be an active `owner`, old
owner loses access, all share links revoked, audited, raises an alert.
*Test:* `test_transfer_of_ownership_for_a_leaver`, `test_transfer_only_to_an_active_owner`. **Closed.**

**T22. A malicious administrator reading documents indirectly.** An admin cannot
read a document, but can (a) create an owner-role account they control and
transfer the document to it, or (b) reset a user's password and sign in as them.
**Accepted, knowingly.** Both leave a trail an admin cannot erase
(`user_created` / `password_reset_by_admin` + `ownership_transferred`, all
hash-chained) and the transfer raises an alert. Closing it needs two-person
approval for transfers and resets, and notifying the affected user; that is the
first thing I would build next.

## C. Taking access away

**T23. Revoked access keeps working.** Cached permissions, a long-lived JWT, a
pre-signed URL. *Defence:* no caching: every request re-reads grants; sessions are
server-side rows (deleting one ends it); no tokens that outlive a revocation.
*Cost:* two indexed queries per document request, and file bytes always pass
through the app server (bandwidth, no CDN).
*Tests:* `test_revoking_a_grant_takes_effect_on_the_next_request` (×3),
`test_downgrading_edit_to_read_stops_edits_immediately`. **Closed.**

**T24. What was already downloaded.** **Accepted:** a copy taken before revocation
cannot be recalled. The audit trail records exactly who downloaded which version
(with SHA-256) and when, which is what an investigation needs.

**T25. A download in flight at the moment of revocation.** **Accepted:** the
response is assembled and committed before sending, so the window is one request.

**T26. Share links forwarded to someone else.** A share link is a bearer token.
**Accepted by design**, reduced: expiry (max 7 days), optional download cap,
revocation, every use audited with IP, alert on token guessing. Next step would be
recipient-bound links (one-time e-mail code).

**T27. Revoked share link served from a cache.** *Defence:* `Cache-Control: no-store`
on every dynamic response. **Closed.**

**T28. Share links resurrected by delete → restore.** *Defence:* deletion revokes
links permanently. *Test:* the last part of `test_share_link_respects_limit_revocation_expiry_and_deletion`. **Closed.**

**T29. A leaver's links and sessions.** *Defence:* deactivation ends sessions;
ownership transfer revokes the old owner's links. **Closed.**

**T30. A token holder extending or un-revoking a link.** Even through a bug in
the app. *Defence:* guard trigger: a token holder may only add one to the counter;
an owner may only revoke, never un-revoke or extend.
*Tests:* `test_token_holder_cannot_extend_unrevoke_or_reset_a_link`,
`test_owner_cannot_unrevoke_a_link`, mutation 20. **Closed.**

**T31. Two requests racing for the last allowed download.** *Defence:*
compare-and-set on the counter. *Test:* `test_two_requests_cannot_both_use_the_last_download`
(simulates the race deterministically), mutation 29. **Closed.**

## D. Accounts and sessions

**T32. Password guessing.** *Defence:* 10 attempts/min per IP and per e-mail; 5
failures lock the account for 15 minutes; scrypt (memory-hard) hashes.
*Tests:* `test_lockout_after_repeated_failures`, `test_login_rate_limit`.
**Partial:** the per-IP limiter lives in each worker's memory (the DB lockout holds
across workers); an attacker can deliberately lock a victim's account (DoS).

**T33. User enumeration.** *Defence:* one message for unknown e-mail, wrong
password, locked and deactivated; unknown e-mails are verified against a dummy
hash so timing matches. *Test:* `test_unknown_and_wrong_password_look_the_same`. **Closed.**

**T34. Session fixation.** *Defence:* a new random token at every sign-in.
*Test:* `test_every_login_gets_a_new_token`. **Closed.**

**T35. Stolen session token.** *Defence:* `HttpOnly`, `Secure`, `SameSite=Lax`;
stored only as SHA-256 (a database dump yields no usable sessions); 30-minute idle
and 8-hour absolute expiry; logout deletes server-side.
*Tests:* `test_session_tokens_are_stored_hashed`, `test_logout_kills_the_token_server_side`, `test_idle_session_expires`.
**Partial:** a token stolen from a live browser works until it expires or the user signs out.

**T36. CSRF.** *Defence:* per-session token on every unsafe method; JSON APIs
require `application/json`; `Sec-Fetch-Site: cross-site` refused; `SameSite` cookies.
*Tests:* `test_state_changes_require_the_csrf_token`, `test_cross_site_requests_are_refused`,
`test_json_endpoints_refuse_form_encoded_bodies`, mutation 27. **Closed.**

**T37. Audit framing by forced download.** If download were a `GET`, any web page
could make a signed-in victim's browser fetch a confidential file, and the audit
trail would then say the *victim* read it. That poisons the evidence the system
exists to produce. *Defence:* downloads are `POST` + CSRF token. *Test:*
`test_download_cannot_be_triggered_by_a_plain_link`. **Closed.**

**T38. Login CSRF.** An attacker signs the victim into the attacker's account; the
victim then uploads a confidential file into it. *Defence:* cross-site `POST`s are
refused via `Sec-Fetch-Site`. **Partial:** very old browsers do not send that header.

**T39. Weak passwords.** 12-character minimum. **Accepted:** no breached-password check.

## E. Uploads and content

**T40. Stored XSS through an uploaded file** (HTML, SVG, XML rendered in our origin).
*Defence:* allowlist decided from the bytes; markup refused even with a `.txt` name;
every download is `application/octet-stream` + `attachment` + `nosniff`; strict CSP.
*Tests:* `test_markup_and_scripts_are_refused`, `test_downloads_are_never_rendered_or_cached`. **Closed.**

**T41. Stored XSS through names, labels, filenames shown in pages.** *Defence:*
Jinja autoescaping; CSP `script-src 'self'` with no inline script. **Closed.**

**T42. Disguised executables.** An `.exe` renamed `.pdf`. *Defence:* the extension
must match the detected type. *Tests:* `test_extension_must_match_contents`,
`test_disguised_and_active_files_are_rejected`, mutation 28. **Closed.**

**T43. Malicious PDFs.** *Defence:* PDFs with `/JavaScript`, `/JS`, `/Launch` or
`/EmbeddedFile` are refused; PDFs are never rendered in our origin.
**Partial:** a byte scan cannot see inside compressed object streams; a real PDF
sanitiser was out of scope.

**T44. Macro documents.** `.docm`/`.xlsm` are not allowed and any `vbaProject.bin`
inside a `.docx`/`.xlsx` is refused. *Test:* `test_macro_documents_are_refused`. **Closed.**

**T45. Zip bombs and oversized uploads.** *Defence:* body size limit enforced
before reading; per-entry compression ratio, entry count and total expanded size
limits. *Tests:* `test_zip_bomb_is_refused`, `test_oversized_upload_is_rejected_before_storage`.
**Partial:** up to 10 MB per upload is held in memory.

**T46. Path traversal through file names.** *Defence:* names are display-only and
sanitised; storage keys are random. *Test:* `test_filenames_are_sanitised`. **Closed.**

**T47. Header injection through file names** (`"` and CR/LF in Content-Disposition).
*Defence:* ASCII fallback plus RFC 5987 encoding. *Test:* `test_hostile_filename_cannot_inject_headers`. **Closed.**

**T48. Right-to-left override spoofing** (`invoice‮fdp.exe` shown as `invoiceexe.pdf`).
*Defence:* bidi control characters stripped. **Closed.**

**T49. Malware stored and shared.** **Accepted:** no antivirus scanning (no
ClamAV on Render's free tier). Files are encrypted at rest and never executed server-side.

**T50. Filling the database.** **Accepted:** the free Postgres has 1 GB. Per-file
limit only; per-user quotas would be next.

## F. The audit trail

**T51. Quietly changing or deleting audit rows.** *Defence:* triggers refuse
UPDATE, DELETE and TRUNCATE for everyone including the app's own login; every row
is hash-chained; admins can verify on demand, and the dashboard alerts if the chain
is broken.
*Tests:* `test_rows_cannot_be_changed_deleted_or_truncated`, `test_editing_a_past_row_is_detected`,
`test_removing_a_row_is_detected`, `test_broken_chain_raises_a_critical_alert`, mutations 21-23. **Closed.**

**T52. Rewriting the whole chain with database-owner rights.** Disable the
triggers, edit history, recompute every hash.
*Defence:* `scripts/anchor_head.py` publishes the chain head outside the database
(a different repository, a write-once bucket, an e-mail); a rewritten chain will
not contain a head you recorded earlier.
**Partial:** only as good as how often you anchor, and the app's login can disable
triggers because it owns the table. Separate roles (T12) would fix the latter.

**T53. Refused attempts vanishing.** A refusal rolls back the request's
transaction, which would roll back its audit row too. *Defence:* refusals are queued
and written in a fresh transaction after the rollback.
*Tests:* `test_refused_attempts_are_recorded_with_who_and_what`, mutation 24. **Closed.**

**T54. An action that happened without an audit row.** *Defence:* the action and its
audit row share a transaction, and the response is sent only after the commit
succeeds; if the commit fails the client gets a 500, not the file. **Closed.**

**T55. Log injection.** Newlines, NUL bytes, fake fields in user agents or names.
*Defence:* events are structured JSON columns, never concatenated strings;
control characters are replaced. **Closed** (see T13).

**T56. CSV formula injection in the export.** An attacker sets their User-Agent to
`=cmd|...`; the auditor opens the export in Excel. *Defence:* cells starting with
`= + - @` are prefixed with `'`. *Test:* `test_csv_export_neutralises_formulas`. **Closed.**

**T57. Spoofed IP addresses in the record.** *Defence:* only the entry appended by
our own proxy (rightmost `X-Forwarded-For` hop) is trusted.
*Test:* `test_client_ip_ignores_client_supplied_forwarded_entries`.
**Partial:** relies on Render appending the address, which is the standard behaviour.

**T58. Two writers forking the chain.** *Defence:* transaction-scoped advisory lock
around each append. **Closed.**

**T59. Non-admins reading the trail.** *Test:* `test_only_admins_can_read_the_audit_trail`,
`test_admin_only_endpoints_refuse_everyone_else`. **Closed.**

**T60. Timestamps.** **Accepted:** `at` is set by the application server's clock.

## G. AI

**T61. The AI widening access by itself.** *Defence:* the suggestion code has no
path that writes grants. Accepting a suggestion calls the same `grant()` function,
with the same authorization, as a manual grant, performed by the signed-in owner.
Suggestion, decision and grant are all audited.
*Tests:* `test_suggestions_never_grant_anything_by_themselves`,
`test_accepting_creates_the_grant_and_both_steps_are_audited`. **Closed.**

**T62. Prompt injection through document names.** *Defence:* the name is passed as
JSON data with an instruction to treat it as data; the model's answer is accepted
only if every id is from the candidate list we supplied; permission is clamped;
reasons are length-capped and stripped. Worst case is a bad suggestion, which a
human still has to accept. **Closed.**

**T63. Confidential content sent to a third party.** *Defence:* the model sees
metadata only (name, category, the owner's own past sharing), never file contents. **Closed.**

**T64. Accepting a suggestion through another document, or someone else's.**
*Tests:* `test_a_suggestion_cannot_be_accepted_through_another_document`,
`test_nobody_else_can_act_on_suggestions`. **Closed.**

**T65. Suggestions as a user-directory leak.** *Defence:* candidates are only people
the owner has already shared with. **Closed.**

## H. Platform and operations

**T66. Secrets in the repository or default keys in production.** *Defence:*
environment variables only; Render generates them; the app refuses to start in
production without real keys. **Closed.**

**T67. Losing the master key.** **Accepted:** if `MASTER_KEY` is lost or changed,
every stored file is unreadable. No key rotation yet (it would re-wrap the per-file
keys, not re-encrypt files).

**T68. A superuser connection silently bypassing RLS / RLS not forced.**
*Tests:* `test_the_application_user_is_not_a_superuser`,
`test_rls_is_forced_on_every_protected_table`, mutation 18. **Closed.**

**T69. Clickjacking.** `frame-ancestors 'none'` and `X-Frame-Options: DENY`. **Closed.**

**T70. Share tokens leaking through logs and Referer.** *Defence:* the link is
`/share#<token>`. The fragment is never sent to any server, so the token stays out
of Render's request logs and proxies; the page script moves it into a POST body and
removes it from the address bar; `Referrer-Policy: no-referrer`. **Closed.**

**T71. Host header in generated share links.** The link shown to the owner is built
from the request's host. **Accepted:** only the owner's own request is reflected
to the owner, and Render routes by host.

**T72. Free-tier operations.** The free database expires after 30 days and has no
backups; the web service sleeps after 15 idle minutes. **Accepted for a demo**;
the README says to upgrade the database before judging.

**T73. Vulnerable dependencies.** Five direct dependencies. **Accepted:** no
automated scanning yet (`pip-audit` in CI would be next).

**T74. Denial of service in general.** **Accepted** beyond the limits above.

## I. Tests that test nothing

**T75. A suite that passes with a check removed.** The brief says you will delete
one authorization check and rerun the tests. *Defence:* `scripts/mutation_check.py`
does that for 29 checks across both locks, sessions, CSRF, uploads, audit and the
share race, and CI runs it on every push. My first run caught 25/29; the four
survivors were real gaps (a redundant trigger branch, the inactive-user session
check, the share-counter race, a token-holder trigger branch), now covered by
dedicated tests: 29/29.
