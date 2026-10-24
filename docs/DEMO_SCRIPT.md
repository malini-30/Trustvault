# Five-minute demo script

Open the live URL a minute before recording (free instances sleep after 15 idle
minutes). Use two browser profiles (or one normal + one private window) so two
people are signed in at once.

| Time | Show | Say |
|---|---|---|
| 0:00-0:30 | README top, `app/authz.py`, `migrations/002_rls.sql` | "Every request is authorised twice: by this one function, and by the database. Each is tested on its own." |
| 0:30-1:15 | **Alice**: upload a PDF (HR). Show the document page: versions with SHA-256, "Only you can see this document". | "The type is checked from the bytes; the file is encrypted with its own key before storage." |
| 1:15-2:00 | Alice grants **Victor** read. Victor (other window) sees it in search and downloads it. | "Grants are per document, to a named person." |
| 2:00-2:40 | Alice revokes. Victor clicks Download again **without refreshing or signing out**: 404. | "Revocation works on the next request. Nothing is cached, and no download URL outlives it." |
| 2:40-3:20 | **Eve** in a terminal: `./scripts/attack_smoke.sh <url> <doc-id>`. All 401/403/404. | "Same answer for 'forbidden' and 'doesn't exist'. Every refusal is recorded." |
| 3:20-3:50 | **Admin** dashboard: the refused attempts list, the "probing" alert for Eve, then try to download: 404. | "Admins investigate; they can't read files." |
| 3:50-4:20 | Alice → "Suggest who should see this" → suggestion appears → Accept. Admin audit filtered to `permission_only`: suggestion, acceptance, grant. | "The AI only suggests. The owner's click creates the grant, through the normal code path." |
| 4:20-5:00 | Admin → **Verify audit chain** (intact). Terminal: `UPDATE audit_events ...` refused by the trigger. Then `python scripts/mutation_check.py` output (29/29). | "The trail can't be edited, any edit would break the hash chain, and the tests fail if any one authorization check is deleted." |

Tip: record the mutation-check output beforehand (it takes ~6 minutes) and show
the saved result.
