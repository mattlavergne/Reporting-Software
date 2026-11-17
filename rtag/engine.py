"""Report execution: SQL / Crystal / SSRS runners, exporters, and delivery."""
import csv
import html
import io
import json
import os
import re
import shlex
import smtplib
import subprocess
import tempfile
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

import httpx
from sqlalchemy import create_engine, text

from .config import Config
from .models import Report, Version

FORMATS = {
    "csv": "text/csv",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "html": "text/html; charset=utf-8",
    "json": "application/json",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
TABLE_FORMATS = ("csv", "xlsx", "html", "json")  # what SQL reports can emit
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class ReportError(Exception):
    pass


@dataclass
class Result:
    data: bytes
    ext: str
    rows: int | None = None


def safe_name(s: str) -> str:
    return SAFE_NAME.sub("_", os.path.basename(s)).strip("._") or "file"


# ---------------------------------------------------------------- SQL
_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_STRING = re.compile(r"'(?:[^']|'')*'")
_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|merge|grant|revoke|exec|execute|"
    r"into|attach|pragma|xp_\w+|sp_\w+)\b", re.I)


def check_readonly(sql: str):
    """Best-effort guard. The real protection must be a read-only DB login."""
    s = _STRING.sub("''", _COMMENT.sub(" ", sql)).strip().rstrip(";").strip()
    if ";" in s:
        raise ReportError("Multiple statements are not allowed")
    if not re.match(r"(select|with)\b", s, re.I):
        raise ReportError("Only SELECT / WITH queries are allowed")
    m = _FORBIDDEN.search(s)
    if m:
        raise ReportError(f"Keyword not allowed in report SQL: {m.group(0)}")


def _expand_env(url: str) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), url)


def run_sql(cfg: Config, report: Report, ver: Version, params: dict) -> tuple[list[str], list[tuple]]:
    if not report.connection:
        raise ReportError("Report has no database connection")
    check_readonly(ver.source)
    wanted = set(re.findall(r"(?<!:):([A-Za-z_]\w*)", ver.source))
    bound = {}
    for p in report.params:
        if p["name"] in wanted:
            bound[p["name"]] = params.get(p["name"], p.get("default", ""))
    missing = wanted - set(bound)
    if missing:
        raise ReportError(f"Query uses undeclared parameter(s): {', '.join(sorted(missing))}")
    eng = create_engine(_expand_env(report.connection.url))
    try:
        with eng.connect() as c:
            res = c.execute(text(ver.source), bound)
            cols = list(res.keys())
            rows = res.fetchmany(cfg.max_rows + 1)
    except ReportError:
        raise
    except Exception as e:
        raise ReportError(f"Database error: {str(e).splitlines()[0][:300]}")
    finally:
        eng.dispose()
    if len(rows) > cfg.max_rows:
        raise ReportError(f"Result exceeds {cfg.max_rows} rows")
    return cols, [tuple(r) for r in rows]


def export_table(cols: list[str], rows: list[tuple], fmt: str, title="Report") -> bytes:
    if fmt == "csv":
        b = io.StringIO()
        w = csv.writer(b)
        w.writerow(cols)
        for r in rows:
            # neutralise spreadsheet formula injection
            w.writerow(["'" + v if isinstance(v, str) and v[:1] in "=+-@" and len(v) > 1 else v for v in r])
        return b.getvalue().encode("utf-8-sig")
    if fmt == "xlsx":
        from openpyxl import Workbook
        wb = Workbook(write_only=True)
        ws = wb.create_sheet(title[:31] or "Report")
        ws.append(cols)
        for r in rows:
            ws.append([v if isinstance(v, (int, float, str, bool, type(None))) or hasattr(v, "isoformat")
                       else str(v) for v in r])
        out = io.BytesIO()
        wb.save(out)
        return out.getvalue()
    if fmt == "json":
        return json.dumps([dict(zip(cols, r)) for r in rows], default=str, indent=1).encode()
    if fmt == "html":
        e = html.escape
        head = "".join(f"<th>{e(str(c))}</th>" for c in cols)
        body = "".join("<tr>" + "".join(f"<td>{e('' if v is None else str(v))}</td>" for v in r) + "</tr>"
                       for r in rows)
        return (f"<!doctype html><meta charset=utf-8><title>{e(title)}</title>"
                "<style>body{font:14px sans-serif}table{border-collapse:collapse}"
                "td,th{border:1px solid #ccc;padding:3px 8px}th{background:#eee}</style>"
                f"<h2>{e(title)}</h2><table><tr>{head}</tr>{body}</table>").encode()
    raise ReportError(f"Unsupported format for SQL reports: {fmt}")


# ---------------------------------------------------------------- Crystal
def run_crystal(cfg: Config, ver: Version, params: dict, fmt: str, declared: list[dict]) -> Result:
    """Calls an external exporter (no shell). Template tokens: {report} {format} {output} {params}.
    {params} expands to one `name=value` argument per declared parameter."""
    if not cfg.crystal_cmd:
        raise ReportError("Crystal runner not configured (set RTAG_CRYSTAL_CMD)")
    if not ver.stored_path or not Path(ver.stored_path).exists():
        raise ReportError("No .rpt file stored for this version")
    with tempfile.TemporaryDirectory() as td:
        out = str(Path(td) / f"out.{fmt}")
        pairs = [f"{p['name']}={params.get(p['name'], p.get('default', ''))}" for p in declared]
        argv = []
        for tok in shlex.split(cfg.crystal_cmd, posix=os.name != "nt"):
            if tok == "{params}":
                argv += pairs
            else:
                argv.append(tok.replace("{report}", ver.stored_path).replace("{format}", fmt)
                            .replace("{output}", out))
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=cfg.crystal_timeout)
        except subprocess.TimeoutExpired:
            raise ReportError("Crystal export timed out")
        except OSError as e:
            raise ReportError(f"Cannot start Crystal exporter: {e}")
        if p.returncode != 0:
            raise ReportError(f"Crystal exporter failed ({p.returncode}): {(p.stderr or p.stdout)[:400]}")
        if not Path(out).exists():
            raise ReportError("Crystal exporter produced no output file")
        return Result(Path(out).read_bytes(), fmt)


# ---------------------------------------------------------------- SSRS
def run_ssrs(cfg: Config, ver: Version, params: dict, fmt: str, declared: list[dict]) -> Result:
    if not cfg.ssrs_url:
        raise ReportError("SSRS not configured (set RTAG_SSRS_URL)")
    q = {"rs:Format": {"xlsx": "EXCELOPENXML", "docx": "WORDOPENXML"}.get(fmt, fmt.upper()),
         "rs:Command": "Render"}
    for p in declared:
        q[p["name"]] = params.get(p["name"], p.get("default", ""))
    auth = httpx.BasicAuth(cfg.ssrs_user, cfg.ssrs_pass) if cfg.ssrs_user else None
    url = f"{cfg.ssrs_url.rstrip('/')}?{ver.source.strip()}"
    try:
        r = httpx.get(url, params=q, auth=auth, timeout=300)
    except httpx.HTTPError as e:
        raise ReportError(f"SSRS request failed: {e}")
    if r.status_code != 200:
        raise ReportError(f"SSRS returned HTTP {r.status_code}")
    return Result(r.content, fmt)


# ---------------------------------------------------------------- dispatch
def execute(cfg: Config, report: Report, ver: Version, params: dict, fmt: str) -> Result:
    if fmt not in FORMATS:
        raise ReportError(f"Unknown format {fmt}")
    if report.kind == "sql":
        if fmt not in TABLE_FORMATS:
            raise ReportError(f"SQL reports support: {', '.join(TABLE_FORMATS)}")
        cols, rows = run_sql(cfg, report, ver, params)
        return Result(export_table(cols, rows, fmt, report.name), fmt, len(rows))
    if report.kind == "crystal":
        return run_crystal(cfg, ver, params, fmt, report.params)
    if report.kind == "ssrs":
        return run_ssrs(cfg, ver, params, fmt, report.params)
    raise ReportError(f"Unknown report kind {report.kind}")


# ---------------------------------------------------------------- delivery
def deliver_email(cfg: Config, to: list[str], subject: str, body: str, name: str, data: bytes, ext: str):
    if not cfg.smtp_host:
        raise ReportError("SMTP not configured (set RTAG_SMTP_HOST)")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg.smtp_from, ", ".join(to), subject.replace("\n", " ")
    msg.set_content(body)
    mt, _, st = FORMATS[ext].split(";")[0].partition("/")
    msg.add_attachment(data, maintype=mt, subtype=st, filename=name)
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as s:
        if cfg.smtp_starttls:
            s.starttls()
        if cfg.smtp_user:
            s.login(cfg.smtp_user, cfg.smtp_pass)
        s.send_message(msg)


def deliver_folder(cfg: Config, folder: str, name: str, data: bytes) -> Path:
    root = cfg.delivery_root
    dest = (root / folder).resolve()
    if dest != root and root not in dest.parents:
        raise ReportError("Delivery folder escapes the delivery root")
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / name
    target.write_bytes(data)
    return target
