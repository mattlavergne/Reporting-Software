# Report Manager

Internal, on-prem report manager for a department's SQL, Crystal Reports and SSRS reports:
catalogue, run, schedule, deliver, and version them. One Python process, SQLite by default.

## Run it

```bash
pip install -r requirements.txt
python -m rtag            # http://127.0.0.1:8080
python -m pytest          # tests
```

First start prints a one-time `admin` password. Put it behind your corporate HTTPS reverse proxy
(IIS/nginx) and set `RTAG_HTTPS_ONLY=1`, `RTAG_HOST=0.0.0.0`. **Run a single worker process**
(the scheduler lives in-process; multiple workers would run every job N times).

## What it does

| Feature | Status |
|---|---|
| SQL reports with typed-in parameters (bound, never string-interpolated); export CSV/XLSX/HTML/JSON | Done, tested |
| Crystal Reports via an external exporter command | Done, **tested only with a fake exporter** |
| SSRS via URL access (`rs:Format`) | Done, **untested against a real server**; Basic auth only |
| Scheduling (cron) + delivery to email and a network folder | Done; folder tested, email path untested against a real SMTP server |
| Version history (every save = new immutable version, change note required), diff, `.rpt` file history | Done |
| Notes per report, run history, audit of who ran what | Done |
| Roles (admin / editor / viewer), per-report grants for viewers | Done |
| Not built yet | Letter/mail-merge engine, in-app Excel/Word/PDF viewers, report bursting, cascading parameters, Active Directory/LDAP login, SharePoint delivery, PDF export of SQL reports |

## Configuration (environment variables)

`RTAG_DATA_DIR`, `RTAG_DB_URL`, `RTAG_SECRET`, `RTAG_DELIVERY_ROOT` (network folder jobs may write under),
`RTAG_SMTP_HOST/PORT/USER/PASS/FROM/STARTTLS`, `RTAG_SSRS_URL/USER/PASS`, `RTAG_CRYSTAL_CMD`, `RTAG_CRYSTAL_TIMEOUT`,
`RTAG_MAX_ROWS`, `RTAG_MAX_UPLOAD_MB`.

### Crystal Reports

Crystal needs the SAP Crystal runtime, which is Windows-only, so run this app on a Windows host that has it.
The app does not embed Crystal; it calls a small command you provide (a .NET/PowerShell wrapper around the
CrystalDecisions SDK, or an existing CLI exporter). Contract:

```
RTAG_CRYSTAL_CMD="C:\tools\CrystalExport.exe {report} {format} {output} {params}"
```
`{params}` expands to one `name=value` argument per parameter declared on the report. The command must write
the file to `{output}` and exit 0, or print the error to stderr and exit non-zero. No shell is used.

## Security notes

- SQL reports are restricted to a single `SELECT`/`WITH` statement by a keyword filter. **That filter is a
  safety net, not a sandbox.** Give each connection a **read-only database login**; that is the real control.
- Only admins define connections (stored in the app DB; use `${ENV_VAR}` in URLs to keep passwords out of it).
- Passwords: scrypt. CSRF tokens on all POSTs. Login throttling is in-memory per process.
- Generated HTML previews are served with a sandbox CSP. CSV exports neutralise `=`/`+`/`-`/`@` formulas.
- Scheduled jobs can only write under `RTAG_DELIVERY_ROOT`.
