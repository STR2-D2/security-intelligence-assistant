# Data Model Notes

The `vulnerabilities` table stores one row per vulnerability identity. CVE-based records are matched by `cve_id`; no-CVE records are matched by `source`, `title`, and `source_url`.

A single vulnerability row can be enriched by multiple sources. The current schema stores only one primary `source` and `source_url`, so source provenance is intentionally limited until a dedicated provenance table is introduced.
