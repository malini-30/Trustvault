# TrustVault API

Base URL: your deployment (for example `https://trustvault.onrender.com`). All
bodies are JSON unless marked *multipart*. All responses are JSON except
downloads and the CSV export.

## How calls are authenticated

1. `POST /api/auth/login` with `{"email", "password"}`. The response sets an
   `HttpOnly`, `SameSite=Lax` cookie `tv_session` and returns `csrf_token`.
2. Send the cookie on every call, and send `X-CSRF-Token: <csrf_token>` on every
   `POST`, `PATCH` and `DELETE`. Missing or wrong token: **403**.
3. JSON endpoints accept only `Content-Type: application/json` (a cross-site
   HTML form cannot send that without a CORS preflight, which is never approved).

## How refusals look

| Situation | Status |
|---|---|
| Not signed in | 401 |
| Signed in, wrong role for an admin or upload endpoint | 403 |
| **Any document you were not granted, or that does not exist** | **404**, identical in both cases |
| Invalid input (after authorization has passed) | 400 with `message` |
| Too many login or share attempts | 429 |

Every 404 on a document route writes an `access_denied` row to the audit trail.

## "Who may call" key

- **Anyone**: no session needed.
- **Signed in**: any active account.
- **Reader**: the document's owner, or someone holding a `read` or `edit` grant on it.
- **Editor**: the owner, or someone holding an `edit` grant.
- **Owner**: the document's owner only (not editors, not admins).
- **Owner role**: an account whose role is `owner`.
- **Admin**: an account whose role is `admin`. Admins are *not* readers of
  anything unless an owner grants them access like anyone else.

## Session and account

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/auth/login` | Anyone | `{email, password}`. Same 401 message for unknown e-mail, wrong password, locked or deactivated account. 5 failures lock the account for 15 minutes. |
| POST | `/api/auth/logout` | Signed in | Deletes the session server-side. |
| GET | `/api/me` | Signed in | Current user and CSRF token. |
| POST | `/api/me/password` | Signed in | `{current_password, new_password}` (12+ chars). Ends all *other* sessions. |

## Documents

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/documents` | Signed in | Only documents you own or hold a grant on. Query: `q` (name), `owner` (name or e-mail), `category`, `from`, `to` (`YYYY-MM-DD`), `scope=all\|mine\|shared`, `page`. |
| POST | `/api/documents` | Owner role | *Multipart*: `file`, `name` (optional), `category` (`HR`, `Legal`, `Finance`, `Engineering`, `Audit`, `Other`). Type checked from content. 10 MB limit. |
| GET | `/api/documents/{id}` | Reader | Metadata and version list. |
| PATCH | `/api/documents/{id}` | Editor | `{name?, category?}`. Any other field (e.g. `owner_id`) → 400. |
| DELETE | `/api/documents/{id}` | Owner | Moves to trash; revokes every share link permanently. |
| POST | `/api/documents/{id}/restore` | Owner | Only while in trash and within 30 days. |
| POST | `/api/documents/{id}/download` | Reader | Latest version. `POST` + CSRF so another site cannot make your browser download (and be audited as reading) a file. Always `application/octet-stream`, `attachment`. |
| GET | `/api/documents/{id}/versions` | Reader | |
| POST | `/api/documents/{id}/versions` | Editor | *Multipart*: `file`. |
| POST | `/api/documents/{id}/versions/{n}/download` | Reader | Checked against the grant you hold **now**, not when the version was made. |
| GET | `/api/trash` | Signed in | Your own deleted documents. |

## Grants

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/documents/{id}/grants` | Owner | |
| POST | `/api/documents/{id}/grants` | Owner | `{email, permission: "read"\|"edit"}`. Creates or changes a grant. The grantee must be an active user. |
| DELETE | `/api/documents/{id}/grants/{user_id}` | Owner | Effective on the grantee's next request. |

## External share links

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/documents/{id}/shares` | Owner | Never returns tokens (only hashes are stored). |
| POST | `/api/documents/{id}/shares` | Owner | `{expires_hours: 1-168, max_downloads?: 1-1000, label?}`. Returns `token` and `path` (`/share#<token>`) **once**. |
| DELETE | `/api/documents/{id}/shares/{share_id}` | Owner | Revocation is permanent. |
| POST | `/api/share/info` | Anyone with a live token | `{token}`. Name, size, expiry, downloads left. |
| POST | `/api/share/download` | Anyone with a live token | `{token}` (JSON or form field). Counts one download atomically. |

## AI access suggestions

| Method | Path | Who may call | Notes |
|---|---|---|---|
| POST | `/api/documents/{id}/suggestions` | Owner | Proposes up to 3 people. **Grants nothing.** |
| GET | `/api/documents/{id}/suggestions` | Owner | Pending suggestions. |
| POST | `/api/documents/{id}/suggestions/{sid}/accept` | Owner | `{permission?}`. The owner's click is what creates the grant (through the normal grant code path). |
| POST | `/api/documents/{id}/suggestions/{sid}/reject` | Owner | |

## Administration

| Method | Path | Who may call | Notes |
|---|---|---|---|
| GET | `/api/admin/users` | Admin | |
| POST | `/api/admin/users` | Admin | `{email, full_name, role, password}` |
| PATCH | `/api/admin/users/{user_id}` | Admin | `{role?, is_active?}`. Ends all that user's sessions. Cannot target yourself. |
| POST | `/api/admin/users/{user_id}/reset-password` | Admin | `{password}`. Ends all that user's sessions. |
| GET | `/api/admin/documents` | Admin | Metadata of every document. Never content. `?q=` filter. |
| GET | `/api/admin/documents/{id}/access` | Admin | Who can reach it now (grants, live links) and its last 100 events. |
| POST | `/api/admin/documents/{id}/transfer` | Admin | `{new_owner_email}` (must be an active owner). Old owner loses access; their share links are revoked. |
| GET | `/api/admin/audit` | Admin | Query: `action`, `actor`, `document_id`, `outcome=success\|denied\|failure`, `permission_only=1`, `limit` (≤1000). |
| GET | `/api/admin/audit/verify` | Admin | Recomputes the whole hash chain; reports where it breaks. |
| GET | `/api/admin/audit/head` | Admin | Latest event id + hash, for anchoring outside the database. |
| GET | `/api/admin/audit/export.csv` | Admin | Latest 1000 events, spreadsheet-formula safe. |
| GET | `/api/admin/alerts` | Admin | Probing, token guessing, bulk download, password guessing, mass grants, new-IP logins, ownership transfers, broken chain. |

## HTML pages

The pages under `/` call exactly the same service functions as the API, so the
rules above apply to them unchanged; `tests/test_route_coverage.py` walks every
page route as well as every API route.

## Example

```bash
BASE=https://your-app.onrender.com
curl -s -c jar -H 'Content-Type: application/json' \
     -d '{"email":"alice@trustvault.demo","password":"Alice#Vault2026"}' $BASE/api/auth/login
# -> {"csrf_token":"...","user":{...}}
curl -s -b jar "$BASE/api/documents?category=HR"
curl -s -b jar -H "X-CSRF-Token: <token>" -X POST -o letter.pdf $BASE/api/documents/<id>/download
```
