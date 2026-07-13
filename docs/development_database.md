# Development Database Notes

Task 008 adds database-level uniqueness for vulnerability identity:

- `cve_id` is unique when present. SQLite allows multiple `NULL` values in a unique column.
- No-CVE records are uniquely identified by `source`, `title`, and `source_url` using a partial unique index where `cve_id IS NULL`.

No Alembic migrations exist yet, and the project must not silently drop user data.

For a local development SQLite database that was created before these constraints, rebuild it explicitly:

```powershell
Copy-Item security_intelligence.db security_intelligence.db.bak
Remove-Item security_intelligence.db
.venv\Scripts\python.exe -m app.main
```

This rebuild procedure is only for the local development database. Do not use it for production data.

The `updated_at` model field represents source-provided vulnerability update time. Local database audit timestamps are stored separately in `created_at` and `modified_at`, both using timezone-aware `DateTime(timezone=True)` columns.
