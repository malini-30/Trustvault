# Write-up

## What I built

TrustVault: upload, organise, search and share confidential documents, with
three roles (admin, owner, viewer), per-document read/edit grants to named
people, revocable external share links, versions, a 30-day trash, AI-assisted
(but human-confirmed) access suggestions, an administrator dashboard with
alerts, and a tamper-evident audit trail of every success and every refusal.

Stack: **Python 3.12, Flask, PostgreSQL 16, server-rendered HTML**, deployed on
Render. I picked it because every security property I care about can be pointed
at in a few lines: one authorization function, one SQL file of policies, one
audit module. A single-page app would have doubled the surface (a second router,
tokens in browser storage, CORS) without adding anything the judges can't already
reach through the API.

## The permission model, in my own words

One owner per document. Nobody else sees it until the owner names them, on that
document, with `read` or `edit`. Edit lets you change it, not decide who else
sees it. No folders, groups or inheritance, so a grant can never be wider than
the person granting it can see. The admin runs the system and the investigation
but cannot open files. Share links are for outsiders: one document, an expiry,
an optional download cap, revocable, and every use is recorded.

The decision is made **on the server, on every request, twice**:

1. `app/authz.py:authorize()`: every service function that receives a document id
   calls it first. A refusal is a 404 (indistinguishable from "doesn't exist")
   plus an audit row.
2. PostgreSQL row-level security, forced on every table that holds document data.
   The application tells the database who is asking at the start of each
   transaction; rows that person may not see are simply not returned.

I test them separately: the isolation suite runs with both locks, with only the
app, and with only the database. A mutation script deletes 29 checks one at a
time; the suite fails for every one.

"Taking access away immediately" means: no permission caching, server-side
sessions that can be deleted, no pre-signed storage URLs, and file bytes that
only ever flow through the server after an authorization check. The cost is two
extra indexed queries per request and no CDN for downloads. For confidential
documents that is the right trade.

## What I deliberately did not build, and why

- **Folders and groups.** They are the cause of the brief's "access to forty
  files" story. Groups are the first addition I would make (one table, one clause
  in `decide()` and in each policy).
- **A separate SPA frontend.** More attack surface, no security benefit.
- **Antivirus scanning, PDF sanitising.** Not available on the free tier; files
  are never rendered in our origin instead (THREATS T43, T49).
- **SSO / MFA.** Real systems need them; a week is better spent on the
  authorization model. Sessions are server-side, so adding them later is local.
- **Retention rules per category, legal hold, e-discovery export.** Out of scope;
  the trash has a fixed 30-day window.
- **Two-person approval for admin transfers and password resets.** I know this is
  the remaining insider route (THREATS T22); it is audited and alerted instead.

## How I used AI, and where it was wrong

I used Claude throughout: for scaffolding, SQL policies, tests and documentation,
with a reusable context file (`ai-context/SECURITY_RULES.md`) and a review
checklist. The tool was fast and mostly right, and confidently wrong in exactly
the places the brief warns about. Details and fixes are in `PROMPTS.md`; the
short version:

- A trigger that looked correct crashed every share-link creation (plpgsql
  evaluates `NEW.user_id` even behind a false `AND`).
- The database policy and the application disagreed about trashed documents;
  only the "database lock only" test mode exposed it.
- An UPDATE refused by row-level security matches zero rows silently, and the
  generated code reported success.
- A NUL byte in a URL made the audit insert fail, turning a refusal into an
  unlogged 500.
- 140 green tests still let 4 deleted checks through. The mutation script found
  them; now 29/29 are caught.

The pattern I took away: generated security code needs a test that fails
without it, and generated tests need a mutation that proves they can fail.

## What is unfinished

- The application connects to PostgreSQL as the table owner, so a successful SQL
  injection could disable RLS. Separate migration and runtime roles would fix it
  (THREATS T12). Render's free database has a single user.
- Chain anchoring is a script you schedule yourself, not built in.
- Rate limiting is per worker process; the database-backed account lockout is the
  limit that holds across workers.
- No key rotation for `MASTER_KEY`.
- Share links are bearer tokens; recipient verification is not built.
- `audit.verify()` loads the whole trail into memory: fine for a demo, not for
  millions of events (it would verify in pages, from the last anchor).
- The free Render database expires after 30 days unless upgraded.
