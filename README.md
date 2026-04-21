# Lovable Hosted App Exposure Audit

Defensive scanner for checking whether published Lovable app URLs expose sensitive paths like `/.env` and `/.git/*`.

## Current Status (April 21, 2026)

- As of April 21, 2026, Lovable public docs do not document a clear self-serve flow for generating a general Lovable platform/API key.
- Documented guidance is to contact `support@lovable.dev` for API access and key generation.
- For security incident context, you can also contact `security@lovable.dev`.

References:
- https://lovable.dev/faq/backend/apis/lovable-api-key
- https://lovable.dev/faq/backend/apis
- https://docs.lovable.dev/integrations/lovable-api

## What It Does

- Visits each target app URL and records homepage status/title.
- Probes high-risk paths:
  - `/.env`, `/.env.local`, `/.env.production`
  - `/.git/HEAD`, `/.git/config`, `/.git/index`, `/.git/logs/HEAD`
- Scans frontend JS bundles for Supabase credential patterns:
  - Supabase project URL (`https://<ref>.supabase.co`)
  - JWT roles in bundled keys (flags non-`anon` roles)
  - High-risk markers (`service_role`, `sb_secret_*`, `postgres://`, etc.)
- Classifies findings (`high`, `medium`, `low`, `none`).
- Redacts likely secrets in evidence snippets.
- Writes JSON + Markdown reports under `reports/`.

## Quick Start

1. Copy target URLs:
   - `cp targets.example.txt targets.txt`
   - Edit `targets.txt` to include all project published URLs/custom domains.
2. Run:
   - `bun run audit --targets-file targets.txt`
3. Open generated report files in `reports/`.

Exit code:
- `0` = no high/medium findings
- `2` = at least one high/medium finding

## Optional API Discovery Mode

If you have an internal/project-list API endpoint, you can let the tool discover target URLs first:

```bash
LOVABLE_API_BASE_URL="https://your-api.example.com" \
LOVABLE_API_PROJECTS_PATH="/v1/projects" \
LOVABLE_API_TOKEN="..." \
bun run audit
```

Notes:
- The script expects JSON and extracts URL-like fields such as `publishedUrl`, `liveUrl`, `url`, `domain`, etc.
- Official Lovable public API docs currently focus on Build with URL links, so project-list discovery usually requires your own internal endpoint/export.

## Environment Variables

- `LOVABLE_TARGETS_FILE`
- `LOVABLE_PROJECT_URLS` (comma-separated URLs)
- `LOVABLE_AUDIT_OUTPUT_DIR`
- `LOVABLE_AUDIT_TIMEOUT_MS`
- `LOVABLE_AUDIT_CONCURRENCY`
- `LOVABLE_AUDIT_PATHS` (comma-separated paths)
- `LOVABLE_API_BASE_URL`
- `LOVABLE_API_PROJECTS_PATH`
- `LOVABLE_API_TOKEN`

## Safety

- Use only against systems you own or are explicitly authorized to test.
- Keep reports confidential; they may still contain sensitive metadata.
